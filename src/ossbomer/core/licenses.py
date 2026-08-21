"""Normalize declared licenses to SPDX.

An SBOM states a license in whichever slot its generator reached for. CycloneDX
offers three -- ``expression`` (an SPDX expression), ``license.id`` (an SPDX
identifier) and ``license.name`` (free text, for when the generator could not
pin an identifier) -- and SPDX documents carry concluded and declared fields
that may hold anything from a clean identifier to ``NOASSERTION``.

Everything downstream wants one thing: a canonical SPDX expression. Policy
evaluation is keyed on identifiers, and a policy cannot answer a question about
``"BSD-like"``. Passing raw strings through meant an unpinnable license reached
ospac as an unknown identifier and was quietly evaluated as such.

So each declaration is normalized once, here, and carries the record of what
happened: what the document said, which slot it came from, what it normalized
to, and by what method. A rule can then distinguish three situations a flat
list of strings collapses into one:

* a clean identifier or expression;
* a valid expression sitting in the free-text slot, which is a generator bug
  worth reporting;
* text that cannot be resolved to SPDX at all, which is a real gap in the
  document rather than a syntax complaint.

Normalization is deliberately deterministic. Every mapping is either derived
from the SPDX license index or listed explicitly in :data:`ALIASES` with a
reason. Nothing is inferred by similarity: guessing that ``"BSD"`` means
``BSD-3-Clause`` would produce a confident answer the document does not support,
which is worse than reporting that it could not be resolved.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from .ir import is_null_value

# Where a declaration came from. The slot matters: text in `name` was never
# claimed to be SPDX, so failing it for bad expression syntax misdescribes it.
SOURCE_EXPRESSION = "expression"  # CycloneDX licenses[].expression
SOURCE_ID = "id"                  # CycloneDX licenses[].license.id
SOURCE_NAME = "name"              # CycloneDX licenses[].license.name (free text)
SOURCE_SPDX_FIELD = "spdx-field"  # SPDX licenseConcluded / licenseDeclared

# How a raw value became an SPDX expression.
VIA_EXPRESSION = "spdx-expression"    # parsed cleanly as-is
VIA_SEPARATOR = "separator-rewritten"  # a non-SPDX separator was translated
VIA_CASE = "case-corrected"           # matched an SPDX key ignoring case
VIA_SCANCODE_KEY = "scancode-key"     # matched the lowercase-hyphen form
VIA_DEPRECATED_KEY = "deprecated-key"  # matched a superseded SPDX key
VIA_ALIAS = "alias"                   # matched a curated alias below
VIA_DESCRIPTIVE = "descriptive-name"  # matched an alias through its prose spelling
AMBIGUOUS = "ambiguous"               # names the licence but not which SPDX id
UNRESOLVED = "unresolved"             # could not be resolved; not guessed at
DECLARED_UNKNOWN = "declared-unknown"  # NOASSERTION / NONE: an honest absence

# Separators SPDX does not define, which package ecosystems use anyway. The
# parser raises on all of them, so they are rewritten before it sees the string.
#
# `||` is npm's documented spelling of OR, so it translates to OR.
#
# The rest are lists whose intent is genuinely unstated, and the two readings are
# not equally safe. Policy resolves OR to the *least* restrictive operand and AND
# to the *most*, so reading a list as OR when it meant AND under-reports
# obligations: the run says allowed for something that is not. Reading it as AND
# when it meant OR over-reports, which surfaces for review instead of shipping a
# violation. They are therefore read as AND, and the declaration records that a
# separator was interpreted so a profile can flag it.
SEPARATOR_REWRITES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\s*\|\|\s*"), " OR "),
    (re.compile(r"\s*[;,]\s*"), " AND "),
    (re.compile(r"\s*/\s*"), " AND "),
    (re.compile(r"\s*\|\s*"), " AND "),
)

# Curated aliases, applied only after every index-derived lookup has missed.
#
# The bar for an entry: the mapping must be unambiguous. Spellings of a single
# versioned license qualify. Family names do not, and their absence is the point
# of this table rather than an oversight:
#
#   "BSD"           -- 2-clause or 3-clause, and the choice changes obligations
#   "GPL", "LGPL"   -- version and only/or-later are both unstated
#   "Public Domain" -- not a license; CC0-1.0 is a dedication, not a synonym
#   "Apache"        -- 1.0, 1.1 and 2.0 all exist
#
# Those stay unresolved on purpose, and a profile reports them as such.
# FALLBACK, pending SemClone/ospac#89 -- see the note on AMBIGUOUS_NAMES below.
# ospac already supplies 1471 mappings; these 25 are the folk spellings it does
# not carry yet. Adding to this table is the wrong direction: add to ospac.
ALIASES: dict[str, str] = {
    # Apache 2.0: version is explicit in every spelling here.
    "apache 2": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache v2": "Apache-2.0",
    "apache v2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license v2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    # MIT: "Expat" is the licence's other common name, not a different licence.
    "mit license": "MIT",
    "the mit license": "MIT",
    "expat": "MIT",
    # BSD variants where the clause count is stated.
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "freebsd": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "modified bsd": "BSD-3-Clause",
    # Others whose names carry no version ambiguity.
    "isc license": "ISC",
    "zlib license": "Zlib",
    "the unlicense": "Unlicense",
    "mozilla public license 2.0": "MPL-2.0",
}

# Text that must never resolve, even though something upstream is willing to
# resolve it. Checked before any lookup.
#
# The motivating entry is bare "GPL": license-expression resolves it to
# GPL-1.0-or-later, because that is what the deprecated bare key meant. Nobody
# writing "GPL" in an SBOM today means version 1.0, so accepting that mapping
# would hand back a confident answer that is almost certainly wrong, and policy
# would then evaluate the wrong license. Reporting it unresolved is correct.
#
# Everything else in the family ("BSD", "Apache", "LGPL", ...) is already
# rejected by the parser; this list exists for the exceptions to that.
# FALLBACK, pending SemClone/ospac#89. Which names are too vague to resolve is a
# property of the licence landscape rather than of this tool.
#
# Complete enough to enforce the promise this module makes, though. "Nothing is
# inferred by similarity" was true for most of these only because ospac happened
# not to carry them -- an upstream release adding `bsd -> BSD-3-Clause` would
# have made `normalize("BSD")` return a confident wrong answer, silently, and
# the test protecting it would have failed *after* the behaviour changed rather
# than instead of it. A promise enforced by someone else's omission is not
# enforced.
#
# Only names that identify a family without identifying a licence belong here.
# Free text ("see LICENSE file") is unresolvable structurally and needs no entry.
NEVER_RESOLVE: set[str] = {
    "gpl", "gpl+",
    # Version unstated, and the versions differ in obligations.
    "lgpl", "agpl", "apache", "mpl", "cddl", "epl", "cc",
    # Which of the family, unstated. BSD alone spans 0/2/3/4-clause.
    "bsd",
    # Not licences: a posture, a category, or an absence of one.
    "public domain", "proprietary", "commercial", "closed source",
    "open source", "free", "freeware", "shareware", "other", "none",
    # "-like" and "-style" are explicit statements that it is *not* that licence.
    "bsd-like", "bsd style", "bsd-style", "mit-like", "mit style", "mit-style",
    "gpl-like", "gpl style", "apache-like", "apache style",
    # The same families written out. `descriptive_key` strips a leading "The"
    # and the word "Version", not the word "License", so "Apache License" is a
    # different key from "apache" and needs its own entry -- otherwise the bare
    # token is refused while the spelling most SBOMs actually use is not.
    #
    # Only families whose versions differ. "MIT License", "ISC License" and
    # "Zlib License" name exactly one licence and stay resolvable, and a version
    # makes any of these specific again: "Apache License 2.0" is a different key
    # and still resolves.
    "apache license", "bsd license", "gpl license", "lgpl license",
    "agpl license", "mpl license", "epl license", "cddl license",
    "cc license", "gnu license", "gnu general public license",
    "gnu lesser general public license", "gnu affero general public license",
    # And spelled out in full. Three rounds of review found this list short by
    # one spelling each time -- abbreviations, then "<family> License", now the
    # written-out names -- so `test_every_versioned_family_is_refused_unversioned`
    # generates the shapes from SPDX data rather than trusting this list to be
    # complete. Entries here are what that test requires; add to both or neither.
    "eclipse public license", "mozilla public license",
    "common development and distribution license",
    "common public license", "eclipse distribution license",
    "apache software license", "the apache software license",
    "creative commons", "gnu library general public license",
}

# Where operators and aliases can be extended without editing this package.
#
# License spellings drift constantly: ecosystems invent separators, vendors ship
# house styles, and an adopter often knows their own suppliers' habits better
# than any shipped table does. Overlays are read from files named in
# OSSBOMER_LICENSE_ALIASES (os.pathsep-separated) and from any package
# registering the `ossbomer.license_aliases` entry point, mirroring how profiles
# and validators already extend.
#
# Overlay format (YAML or JSON), every key optional::
#
#     aliases:
#       "acme proprietary v2": LicenseRef-ACME-2.0
#     never_resolve:
#       - "internal"
#     separators:
#       '\s+/\s+': " OR "     # regex -> SPDX operator
#
# Overlays are applied after the built-ins and win on conflict, so an adopter
# can override a shipped mapping they disagree with.
ENV_ALIASES = "OSSBOMER_LICENSE_ALIASES"
ENTRY_POINT_GROUP = "ossbomer.license_aliases"

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class LicenseDeclaration:
    """One license as the document stated it, plus what it normalizes to."""

    raw: str
    source: str
    normalized: str | None = None
    method: str = UNRESOLVED

    @property
    def resolved(self) -> bool:
        """True when this carries a usable SPDX expression."""
        return self.normalized is not None

    @property
    def ambiguous(self) -> bool:
        """The text names a licence, but not precisely enough for an SPDX id.

        Distinct from plain unresolved. "GNU LESSER GENERAL PUBLIC LICENSE,
        Version 2.1" identifies the licence and the version and still does not
        say whether later versions are permitted, which is the whole difference
        between `LGPL-2.1-only` and `LGPL-2.1-or-later`. Both remain
        unresolved -- but "I do not recognise this" and "this is not specific
        enough to be an identifier" send a reader to different fixes.
        """
        return self.method == AMBIGUOUS

    @property
    def declared_unknown(self) -> bool:
        """True when the document explicitly said it does not know."""
        return self.method == DECLARED_UNKNOWN

    @property
    def misplaced(self) -> bool:
        """A valid SPDX expression declared in the free-text slot.

        Not a document-quality problem so much as a generator one: a consumer
        reading only `expression` and `license.id` would miss this license
        entirely, even though it is perfectly well formed.
        """
        return (self.source == SOURCE_NAME
                and self.resolved
                and self.method in (VIA_EXPRESSION, VIA_CASE, VIA_SCANCODE_KEY))

    @property
    def effective(self) -> str:
        """What downstream layers should use: the SPDX form when there is one."""
        return self.normalized if self.normalized is not None else self.raw


# The function ospac would expose to become the single source of alias data.
# Preferred over reading its shipped records, and absent today: see
# `_ospac_aliases` for what happens meanwhile.
OSPAC_ALIAS_API = "license_aliases"


@lru_cache(maxsize=1)
def _ospac_aliases() -> dict[str, str]:
    """Alias data from ospac, if it is installed.

    ospac is the source of truth for license metadata across these tools: it
    regenerates its records from SPDX releases, so mappings that derive from
    SPDX belong there rather than being re-curated in every consumer. A
    hand-held list is not wrong when written -- it is wrong two SPDX releases
    later, quietly, and differently in each consumer keeping its own copy.

    The built-in tables above are a fallback for when ospac is absent, tracked
    for removal in SemClone/ospac#89.

    Two ways to get them, tried in order:

    1. ``ospac.license_aliases()`` -- a mapping of lowercased alias to SPDX
       identifier. This does not exist yet. It is the contract to add there,
       because it can carry the folk spellings ("Apache2", "BSD-like") that SPDX
       never publishes and that every consumer currently re-invents.
    2. The shipped license records, which carry the official long name per
       identifier ("Apache License 2.0"). Works today and yields ~712 mappings.

    Optional by design. ospac is the ``[oslc]`` extra, while normalization is
    needed by every profile rather than only the license ones, so the built-in
    tables must stand alone. Missing ospac costs the long names; it does not stop
    normalization working.
    """
    names: dict[str, str] = {}
    try:
        import glob
        import json as _json

        import ospac
    except ImportError:
        return names

    # 1. The public API, once it exists.
    provider = getattr(ospac, OSPAC_ALIAS_API, None)
    if callable(provider):
        try:
            supplied = provider() or {}
            if isinstance(supplied, dict):
                return {_WHITESPACE.sub(" ", str(k)).strip().lower(): str(v)
                        for k, v in supplied.items() if k and v}
        # Third-party code and an unstable shape. Fall through to the records
        # rather than losing normalization entirely, and say so: silently using
        # a weaker source would make a drop in resolved licenses unexplainable.
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(__name__).warning(
                "ospac.%s() failed (%s: %s); falling back to its shipped "
                "license records", OSPAC_ALIAS_API, type(exc).__name__, exc)
    # 2. Fall back to the shipped records. Reaching into another package's data
    #    directory is not a contract, which is exactly why option 1 is preferred.
    directory = os.path.join(os.path.dirname(ospac.__file__), "data", "licenses", "json")
    try:
        paths = glob.glob(os.path.join(directory, "*.json"))
    except OSError:  # pragma: no cover - unreadable install
        return names
    for path in paths:
        # Third-party data whose layout this package does not control. A single
        # unreadable or reshaped record must not cost the other 715.
        try:
            with open(path, "r", encoding="utf-8") as fh:
                record = (_json.load(fh) or {}).get("license") or {}
            name, spdx_id = record.get("name"), record.get("spdx_id")
            if name and spdx_id:
                names[_WHITESPACE.sub(" ", str(name)).strip().lower()] = str(spdx_id)
        except Exception:  # noqa: BLE001, S112
            continue
    return names


def _read_overlay(path: str) -> dict[str, Any]:
    """Read one overlay file. YAML covers JSON, so one loader handles both."""
    import yaml
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        # TypeError rather than ValueError: the file parsed fine, it is the
        # wrong shape. The operator named this file, so the error says which.
        raise TypeError(f"{path}: expected a mapping at the top level")
    return data


def _overlay_sources() -> list[dict[str, Any]]:
    """Every overlay, entry points first so files on disk can override them."""
    out: list[dict[str, Any]] = []
    try:
        from importlib.metadata import entry_points
        try:
            eps = entry_points(group=ENTRY_POINT_GROUP)
        except TypeError:  # < 3.10 signature
            eps = entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined,arg-type]
        for ep in eps:
            try:
                loaded = ep.load()
                out.append(loaded() if callable(loaded) else loaded)
            # Third-party code. A broken overlay must not stop a validation run,
            # and must not stop the remaining overlays from loading either.
            except Exception:  # noqa: BLE001, S112
                continue
    except ImportError:  # pragma: no cover
        pass
    for path in (os.environ.get(ENV_ALIASES) or "").split(os.pathsep):
        if path.strip():
            # A named file that cannot be read is an operator error, so unlike
            # the entry points above this is deliberately not swallowed.
            out.append(_read_overlay(path.strip()))
    return out


@lru_cache(maxsize=1)
def _tables() -> tuple[dict[str, str], set[str], tuple[tuple[Any, str], ...],
                       dict[str, str], set[str], dict[str, str], set[str]]:
    """Built-in tables merged with every overlay. Overlays win on conflict.

    Returns the exact tables and their descriptive-key views. The views are
    built here, in the same layering pass, rather than derived afterwards:
    re-keying the merged table later loses which layer each entry came from, so
    two spellings collapsing to one key would be resolved by whichever sorted
    first instead of by which layer declared it. That made an adopter's
    override apply to `"apache software license, version 2.0"` and not to `"The
    Apache Software License, Version 2.0"` -- the same licence, two
    identifiers, decided by an article.
    """
    aliases: dict[str, str] = {}
    descriptive: dict[str, str] = {}
    adopter_aliases: dict[str, str] = {}
    adopter_refusals: set[str] = set()

    def add(key: str, value: str) -> None:
        squashed = _WHITESPACE.sub(" ", str(key)).strip().lower()
        aliases[squashed] = str(value)
        descriptive[descriptive_key(squashed)] = str(value)

    # Layered lowest to highest: ospac's official names, then the curated folk
    # spellings here (which SPDX never publishes), then adopter overlays. Later
    # layers overwrite, in both views.
    for key, value in _ospac_aliases().items():
        add(key, value)
    for key, value in ALIASES.items():
        add(key, value)

    never = set(NEVER_RESOLVE)
    separators = list(SEPARATOR_REWRITES)
    overridden: dict[str, str] = {}
    for overlay in _overlay_sources():
        for key, value in (overlay.get("aliases") or {}).items():
            add(key, value)
            squashed_key = _WHITESPACE.sub(" ", str(key)).strip().lower()
            adopter_aliases[squashed_key] = str(value)
            adopter_aliases[descriptive_key(squashed_key)] = str(value)
            overridden[descriptive_key(str(key))] = str(value)
        for key in overlay.get("never_resolve") or []:
            squashed_refusal = _WHITESPACE.sub(" ", str(key)).strip().lower()
            never.add(squashed_refusal)
            adopter_refusals.add(squashed_refusal)
            adopter_refusals.add(descriptive_key(squashed_refusal))
        for pattern, operator in (overlay.get("separators") or {}).items():
            separators.append((re.compile(str(pattern)), str(operator)))

    # An override reaches every spelling of the name it overrides, including
    # ones that carry a shipped alias of their own. Without this an adopter who
    # remapped "apache software license, version 2.0" still got the shipped
    # `Apache-2.0` for "Apache Software License 2.0" -- the same name, differing
    # only by the punctuation `descriptive_key` exists to ignore. "Overlays win
    # on conflict" has to mean the conflict, not one spelling of it.
    if overridden:
        for key in list(aliases):
            replacement = overridden.get(descriptive_key(key))
            if replacement is not None:
                aliases[key] = replacement

    # A denylist entry has to refuse the spellings the descriptive step would
    # otherwise reach. Refusing only the exact string let `"The Eclipse Public
    # License 2.0"` resolve while `"Eclipse Public License 2.0"` was refused,
    # which is the failure the denylist exists to prevent.
    never_descriptive = {descriptive_key(n) for n in never}

    # What the adopter said, kept apart from the merged tables so `normalize`
    # can consult it before anything else. Subtracting it from the denylist
    # instead produced two bugs in one round: an override lost to the SPDX
    # parser, which runs earlier, and lifting one spelling left the other
    # refused. Order of precedence belongs where precedence is decided.

    return (aliases, never, tuple(separators), descriptive, never_descriptive,
            adopter_aliases, adopter_refusals)


def reset_caches() -> None:
    """Forget loaded overlays and every normalization decided under them.

    Needed because both the tables and individual results are cached, so a test
    or a long-lived process that changes the overlay set would otherwise keep
    answering from the old ones.
    """
    _tables.cache_clear()
    _ospac_aliases.cache_clear()
    normalize.cache_clear()


# FALLBACK, pending SemClone/ospac#89. This is licence data, so it belongs in
# ospac, which regenerates from SPDX releases. Held here only until ospac
# exposes it, because a hand-maintained list is not wrong on the day it is
# written -- it is wrong two SPDX releases later, quietly, and differently in
# every consumer holding its own copy. Shrink this to nothing as ospac covers
# it; do not grow it.
#
# Prose spellings that name a licence family and version without saying which
# SPDX identifier applies. The GNU licences are the whole of this problem: the
# difference between `-only` and `-or-later` is the copyright holder's grant,
# which the licence's own name does not carry. Resolving either way would assert
# something the document never said.
#
# Matched on the descriptive key below, so case, a leading "The" and
# ", Version 2.1" spellings all land here.
AMBIGUOUS_NAMES: dict[str, str] = {
    "gnu general public license 1.0": "GPL-1.0-only or GPL-1.0-or-later",
    "gnu general public license 2.0": "GPL-2.0-only or GPL-2.0-or-later",
    "gnu general public license 3.0": "GPL-3.0-only or GPL-3.0-or-later",
    "gnu lesser general public license 2.1": "LGPL-2.1-only or LGPL-2.1-or-later",
    "gnu lesser general public license 3.0": "LGPL-3.0-only or LGPL-3.0-or-later",
    "gnu library general public license 2.0": "LGPL-2.0-only or LGPL-2.0-or-later",
    "gnu affero general public license 3.0": "AGPL-3.0-only or AGPL-3.0-or-later",
}

# Noise that carries no meaning in a licence name, stripped before matching so
# one alias entry serves every spelling of it.
_LEADING_THE = re.compile(r"^the\s+")
_VERSION_WORD = re.compile(r",?\s*\bversions?\b\s*", re.IGNORECASE)
_COMMA = re.compile(r"\s*,\s*")


def descriptive_key(text: str) -> str:
    """The comparison form of a prose licence name.

    An SBOM writes the same licence as "Apache License, Version 2.0", "The
    Apache Software License, version 2.0" and "Apache License 2.0" depending on
    which POM it came from, and Maven-sourced documents carry the prose name far
    more often than the identifier. Listing every spelling would be an
    open-ended table; normalising the spelling away is one function.

    Applied to both sides of the lookup, so the alias table stays written in
    whichever form reads naturally.
    """
    key = _WHITESPACE.sub(" ", text).strip().lower()
    key = _LEADING_THE.sub("", key)
    key = _VERSION_WORD.sub(" ", key)
    key = _COMMA.sub(" ", key)
    return _WHITESPACE.sub(" ", key).strip()


@lru_cache(maxsize=1)
def _index() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Build lookup tables from the SPDX license index shipped upstream.

    Returns (by_lowercased_spdx_key, by_scancode_key, by_superseded_key).
    """
    by_key: dict[str, str] = {}
    by_scancode: dict[str, str] = {}
    by_superseded: dict[str, str] = {}
    try:
        from license_expression import get_license_index
    except ImportError:  # pragma: no cover - present via the SBOM parsers
        return by_key, by_scancode, by_superseded
    for entry in get_license_index():
        spdx = entry.get("spdx_license_key")
        if not spdx:
            continue
        by_key.setdefault(spdx.lower(), spdx)
        scancode = entry.get("license_key")
        if scancode:
            by_scancode.setdefault(str(scancode).lower(), spdx)
        for other in entry.get("other_spdx_license_keys") or []:
            by_superseded.setdefault(str(other).lower(), spdx)
    return by_key, by_scancode, by_superseded


def _canonical_expression(text: str) -> str | None:
    """Return the canonical SPDX rendering of `text`, or None if it is not one."""
    try:
        from license_expression import get_spdx_licensing
        licensing = get_spdx_licensing()
    except ImportError:  # pragma: no cover
        return None
    try:
        info = licensing.validate(text)
    # `validate` raises on some malformed input rather than reporting it. See
    # `validators._spdx_license_expression` for the case that motivated this.
    except Exception:  # noqa: BLE001
        return None
    if info.errors:
        return None
    return info.normalized_expression or text


@lru_cache(maxsize=4096)
def normalize(raw: str, source: str = SOURCE_NAME) -> LicenseDeclaration:
    """Resolve one declared license to SPDX, recording how.

    Cached: an 883-component SBOM carried 870 license values and 25 distinct
    ones, so the same strings recur heavily.
    """
    text = "" if raw is None else str(raw).strip()
    if not text or is_null_value(text):
        return LicenseDeclaration(raw=text, source=source, normalized=None,
                                  method=DECLARED_UNKNOWN)

    (aliases, never, separators, descriptive_aliases, never_descriptive,
     adopter_aliases, adopter_refusals) = _tables()
    squashed_early = _WHITESPACE.sub(" ", text).lower()

    descriptive = descriptive_key(squashed_early)

    # -1. What the adopter said, before anything else looks at it.
    #
    #     They know their corpus; this tool does not get to overrule them, and
    #     neither does the SPDX parser. An override used to be applied by
    #     subtracting the name from the denylist further down, which left the
    #     parser answering first: an overlay mapping "gpl" got the parser's
    #     deprecated `GPL-1.0-or-later` rather than the identifier they chose.
    #
    #     A refusal in the same overlay is the more specific statement and is
    #     checked first. Both are matched in either spelling, so a leading "The"
    #     cannot make an adopter's own rule apply to one form and not the other.
    if squashed_early in adopter_refusals or descriptive in adopter_refusals:
        return LicenseDeclaration(text, source, None, UNRESOLVED)
    adopted = adopter_aliases.get(squashed_early)
    if adopted:
        return LicenseDeclaration(text, source, adopted, VIA_ALIAS)
    adopted = adopter_aliases.get(descriptive)
    if adopted:
        # Matched through the prose spelling, and recorded as such: the method
        # says how it matched, not who declared it.
        return LicenseDeclaration(text, source, adopted, VIA_DESCRIPTIVE)

    # 0. Refuse anything on the denylist before anything else gets a chance to
    #    resolve it. Bare "GPL" is accepted upstream as GPL-1.0-or-later, and
    #    letting that through would be a confident wrong answer.
    #
    #    Both spellings, and both here rather than later: a denylist checked
    #    after the alias lookups is not a denylist. `never_resolve: ["MIT
    #    License"]` refused that string and then resolved "The MIT License"
    #    through a shipped alias further down.
    if squashed_early in never or descriptive in never_descriptive:
        return LicenseDeclaration(text, source, None, UNRESOLVED)

    # 1. Already an SPDX expression or identifier. Covers the common case and,
    #    deliberately, a well-formed expression sitting in the free-text slot.
    #    `+`, `-or-later`, `-only`, lowercase and/or/with, and nesting are all
    #    handled by the parser itself and need nothing here.
    canonical = _canonical_expression(text)
    if canonical:
        return LicenseDeclaration(text, source, canonical, VIA_EXPRESSION)

    # 1b. Named, but not precisely enough to be an identifier. Above every
    #     lookup, because any of them can answer with a confident id: an overlay
    #     alias for "gnu lesser general public license 2.1" resolved it to
    #     LGPL-2.1-only under one spelling while another spelling reported the
    #     ambiguity, which is the same document getting two answers.
    #
    #     Below step 1 on purpose. Ambiguity is a property of the prose name,
    #     not of the licence, so `LGPL-2.1-only` and the deprecated `LGPL-2.1`
    #     still resolve through SPDX's own mapping.
    if descriptive in AMBIGUOUS_NAMES:
        return LicenseDeclaration(text, source, None, AMBIGUOUS)

    # 2. The same string with ecosystem separators translated to SPDX operators.
    rewritten = text
    for pattern, operator in separators:
        rewritten = pattern.sub(operator, rewritten)
    if rewritten != text:
        canonical = _canonical_expression(rewritten)
        if canonical:
            return LicenseDeclaration(text, source, canonical, VIA_SEPARATOR)

    by_key, by_scancode, by_superseded = _index()
    squashed = squashed_early

    # 3. An SPDX key in the wrong case: "mit" -> "MIT".
    if squashed in by_key:
        return LicenseDeclaration(text, source, by_key[squashed], VIA_CASE)

    # 4. A superseded key the index maps forward.
    if squashed in by_superseded:
        return LicenseDeclaration(text, source, by_superseded[squashed],
                                  VIA_DEPRECATED_KEY)

    # 5. The ScanCode lowercase-hyphen spelling: "apache-2.0" -> "Apache-2.0".
    if squashed in by_scancode:
        return LicenseDeclaration(text, source, by_scancode[squashed],
                                  VIA_SCANCODE_KEY)

    # 6. A curated alias. Deliberately last, and deliberately small.
    alias = aliases.get(squashed)
    if alias:
        return LicenseDeclaration(text, source, alias, VIA_ALIAS)

    # 7. The same aliases, matched through the prose spelling: a leading "The",
    #    ", Version 2.0" and stray commas removed from both sides. This is
    #    normalisation rather than inference -- the alias still has to be there.
    alias = descriptive_aliases.get(descriptive)
    if alias:
        return LicenseDeclaration(text, source, alias, VIA_DESCRIPTIVE)

    # 8. Not resolvable without guessing, so it is reported rather than guessed.
    return LicenseDeclaration(text, source, None, UNRESOLVED)
