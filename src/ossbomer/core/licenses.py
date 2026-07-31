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
NEVER_RESOLVE: set[str] = {"gpl", "gpl+"}

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
    SPDX belong there rather than being re-curated in every consumer.

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
def _tables() -> tuple[dict[str, str], set[str], tuple[tuple[Any, str], ...]]:
    """Built-in tables merged with every overlay. Overlays win on conflict."""
    # Layered lowest to highest: ospac's official names, then the curated folk
    # spellings here (which SPDX never publishes), then adopter overlays.
    aliases = dict(_ospac_aliases())
    aliases.update({k.lower(): v for k, v in ALIASES.items()})
    never = set(NEVER_RESOLVE)
    separators = list(SEPARATOR_REWRITES)
    for overlay in _overlay_sources():
        for key, value in (overlay.get("aliases") or {}).items():
            aliases[_WHITESPACE.sub(" ", str(key)).strip().lower()] = str(value)
        for key in overlay.get("never_resolve") or []:
            never.add(_WHITESPACE.sub(" ", str(key)).strip().lower())
        for pattern, operator in (overlay.get("separators") or {}).items():
            separators.append((re.compile(str(pattern)), str(operator)))
    return aliases, never, tuple(separators)


def reset_caches() -> None:
    """Forget loaded overlays and every normalization decided under them.

    Needed because both the tables and individual results are cached, so a test
    or a long-lived process that changes the overlay set would otherwise keep
    answering from the old ones.
    """
    _tables.cache_clear()
    _ospac_aliases.cache_clear()
    normalize.cache_clear()


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

    aliases, never, separators = _tables()
    squashed_early = _WHITESPACE.sub(" ", text).lower()

    # 0. Refuse anything on the denylist before anything else gets a chance to
    #    resolve it. Bare "GPL" is accepted upstream as GPL-1.0-or-later, and
    #    letting that through would be a confident wrong answer.
    if squashed_early in never:
        return LicenseDeclaration(text, source, None, UNRESOLVED)

    # 1. Already an SPDX expression or identifier. Covers the common case and,
    #    deliberately, a well-formed expression sitting in the free-text slot.
    #    `+`, `-or-later`, `-only`, lowercase and/or/with, and nesting are all
    #    handled by the parser itself and need nothing here.
    canonical = _canonical_expression(text)
    if canonical:
        return LicenseDeclaration(text, source, canonical, VIA_EXPRESSION)

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

    # 7. Not resolvable without guessing, so it is reported rather than guessed.
    return LicenseDeclaration(text, source, None, UNRESOLVED)
