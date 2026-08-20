"""Pluggable field validators (R7).

A validator answers: given a value (and some context), does it satisfy the
check? It returns ``(ok, message)``. Validators are referenced from profiles by
name, optionally with parameters, e.g.::

    validators: [present, non_placeholder]
    validators: [{name: hash_algorithm_in_set, algs: [SHA-256, SHA-512]}]

New validators register via :func:`register`; third parties can add their own
through the ``ossbomer.validators`` entry-point group (the plugin escape hatch).
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from functools import lru_cache
from typing import Any, Callable

from .ir import Sbom, is_null_value
from .licenses import AMBIGUOUS_NAMES, descriptive_key

# A validator: (value, ctx, params) -> (ok, message)
ValidatorFn = Callable[[Any, "ValidatorContext", dict], "tuple[bool, str]"]

_REGISTRY: dict[str, ValidatorFn] = {}


class ValidatorContext:
    """Context passed to validators so they can see the whole SBOM if needed."""

    def __init__(self, sbom: Sbom, target: Any = None, path: str = ""):
        self.sbom = sbom
        self.target = target  # the Component/Document/edge under evaluation
        self.path = path


def register(name: str) -> Callable[[ValidatorFn], ValidatorFn]:
    def deco(fn: ValidatorFn) -> ValidatorFn:
        _REGISTRY[name] = fn
        return fn
    return deco


def get(name: str) -> ValidatorFn:
    if name not in _REGISTRY:
        raise KeyError(f"Unknown validator: {name!r} (available: {sorted(_REGISTRY)})")
    return _REGISTRY[name]


def available() -> list[str]:
    return sorted(_REGISTRY)


# ---- placeholder detection ---------------------------------------------------

PLACEHOLDER_RE = re.compile(
    r"^\s*(todo|tbd|changeme|change[_-]?me|xxx+|n/?a|unknown|example|placeholder|"
    r"foo|bar|\$\{.*\}|<.*>|0\.0\.0|1\.0\.0-snapshot)\s*$",
    re.IGNORECASE,
)
SEMVER_RE = re.compile(r"^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")
CALVER_RE = re.compile(r"^\d{4}([.\-]\d{1,2}){1,2}([.\-][0-9A-Za-z]+)?$")


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, dict):
        # A mapping's values are its data. `hashes` is alg -> digest, and a rule
        # asking whether a hash is present means the digest, not the algorithm
        # name. Without this branch the fallback below wrapped the mapping
        # itself, so `{}` came back as `[{}]` and read as populated: `present`
        # returned True for a component or file carrying no hashes at all.
        return list(value.values())
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


# ---- core validators ---------------------------------------------------------

def has_value(value: Any) -> bool:
    """Whether `value` carries something a rule could act on.

    The single answer to "is there data here", used by `present` below and by the
    engine to decide `MUST_WHERE_AVAILABLE` availability and which of a rule's
    alternative `fields` to read. Those three asked the same question in three
    places and drifted twice: an inline null test counted an empty container as
    data, and a key-based mapping check counted `{"sha256": ""}` as data while
    `present` called it absent. Sharing the implementation is what stops that
    happening a third time.
    """
    items = _as_list(value)
    if not items:
        return False
    return not all(isinstance(v, str) and is_null_value(v) for v in items)


@register("present")
def _present(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    items = _as_list(value)
    if not items:
        return False, "field is absent or empty"
    if all(isinstance(v, str) and is_null_value(v) for v in items):
        return False, "field is present but NOASSERTION/NONE/empty"
    return True, ""


@register("non_placeholder")
def _non_placeholder(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    for v in _as_list(value):
        if isinstance(v, str) and PLACEHOLDER_RE.match(v):
            return False, f"placeholder value: {v!r}"
    return True, ""


@register("format_regex")
def _format_regex(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    pattern = params.get("pattern")
    if not pattern:
        return False, "format_regex requires a 'pattern'"
    rx = re.compile(pattern)
    for v in _as_list(value):
        if not (isinstance(v, str) and rx.search(v)):
            return False, f"{v!r} does not match /{pattern}/"
    return True, ""


# RFC 3339 section 5.6 `date-time`, spelled out rather than delegated to
# `datetime.fromisoformat`. That function implements ISO 8601, which is a
# superset: it accepted a bare date, a time without seconds and an offset
# carrying seconds, none of which are RFC 3339, so the check passed values its
# own message called invalid. It is also version-dependent -- before 3.11 it
# rejected fractional seconds of any length but 3 or 6 digits -- which made the
# verdict depend on the interpreter rather than the document.
#
# `partial-time` requires seconds and `time-numoffset` is exactly +-HH:MM, so
# neither may be omitted or extended. Section 5.6 permits lower case `t` and
# `z`, and its note permits a space in place of `T` for readability; both are
# accepted here, and both are unreachable from a real SBOM anyway, since SPDX
# mandates `YYYY-MM-DDThh:mm:ssZ` and CycloneDX an XSD `dateTime`.
# `[0-9]` rather than `\d`, which in Python also matches the decimal digits of
# other scripts: `\d` made `٢٠٢٦-٠١-٠١T٠٠:٠٠:٠٠Z` a valid timestamp, `int()`
# being just as willing to convert it. The ABNF `DIGIT` is ASCII.
_RFC3339_LOCAL = (
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?"
)
_RFC3339 = re.compile(_RFC3339_LOCAL + r"(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))$")
_RFC3339_NO_OFFSET = re.compile(_RFC3339_LOCAL + r"$")

_MINUTES_PER_DAY = 24 * 60
# A leap second is inserted as 23:59:60 UTC, which is the last minute of a UTC
# day however the offset spells it.
_LEAP_SECOND_MINUTE = 23 * 60 + 59


@register("rfc3339_utc")
def _rfc3339_utc(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    for v in _as_list(value):
        s = str(v).strip()
        m = _RFC3339.match(s)
        if not m:
            # A well-formed instant that simply carries no offset is the common
            # mistake and gets its own message; anything else is malformed.
            if _RFC3339_NO_OFFSET.match(s):
                return False, f"{v!r} lacks a UTC/timezone designator"
            return False, f"{v!r} is not an RFC 3339 timestamp"

        year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
        # Checked as a date and a wall time rather than by building a datetime,
        # since second 60 is a leap second (section 5.7) and legal here, but no
        # date library will accept one.
        if hour > 23 or minute > 59 or second > 60:
            return False, f"{v!r} is not a real time"
        try:
            date(year, month, day)
        except ValueError:
            return False, f"{v!r} is not a real date"

        sign, offset_hours, offset_minutes = m.group(7), m.group(8), m.group(9)
        offset = 0
        if offset_hours is not None:
            if int(offset_hours) > 23 or int(offset_minutes) > 59:
                return False, f"{v!r} has an out-of-range UTC offset"
            offset = (int(offset_hours) * 60 + int(offset_minutes))
            offset = -offset if sign == "-" else offset

        # `time-second` allows 60 only under the leap second rules, so it is not
        # a free 61st second of any minute. Section 5.7 puts one at the end of a
        # month, so once the offset is taken off the instant has to be 23:59 UTC
        # on a UTC month's last day. Taking the offset off can move the date, so
        # the day carries: 2017-01-01T05:29:60+05:30 is 2016-12-31T23:59:60Z.
        # Which months actually got one needs the IERS table, which is not worth
        # carrying, so a well-placed leap second is taken at its word.
        if second == 60:
            days, minute_of_day = divmod(hour * 60 + minute - offset,
                                         _MINUTES_PER_DAY)
            try:
                utc_day = date(year, month, day) + timedelta(days=days)
                ends_a_month = (utc_day + timedelta(days=1)).day == 1
            except OverflowError:
                # 0001-01-01 and 9999-12-31 have no neighbouring day to step to.
                # A validator answers, it does not raise: the scorer calls this
                # one directly, outside the engine's guard, so an SBOM dated at
                # the edge of the range would take the whole run down with it.
                ends_a_month = False
            if minute_of_day != _LEAP_SECOND_MINUTE or not ends_a_month:
                return False, (f"{v!r} puts a leap second somewhere other than "
                               "the last minute of a UTC month")
    return True, ""


@lru_cache(maxsize=1)
def spdx_licensing() -> Any:
    """The SPDX licensing index, built once per process.

    `license_expression.get_spdx_licensing()` rebuilds the whole index on every
    call and does no caching of its own. Called per component it dominated
    runtime: on an 883-component SBOM it accounted for 28.7s of a 43.4s run,
    across 1739 rebuilds from the validator and the scorer together.
    """
    from license_expression import get_spdx_licensing
    return get_spdx_licensing()


@register("spdx_license_expression")
def _spdx_license_expression(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    try:
        licensing = spdx_licensing()
    except ImportError:  # pragma: no cover - dependency always present via parsers
        return True, "license-expression not available; skipped"
    for v in _as_list(value):
        if not isinstance(v, str) or is_null_value(v):
            continue
        # `validate` can raise rather than report, on strings real SBOMs
        # actually carry: "MIT (http://mootools.net/license.txt)" trips an
        # AttributeError inside license-expression itself. A parser that
        # explodes on a value is still telling us the value is not a valid
        # expression, so it is reported as one rather than taking the run down.
        # `scorer._spdx_expr_ok` has always guarded this; this path had not.
        try:
            parsed = licensing.validate(v)
        except Exception:  # noqa: BLE001
            return False, f"{v!r} could not be parsed as an SPDX license expression"
        if parsed.errors:
            return False, f"{v!r} is not a valid SPDX license expression"
    return True, ""


@register("license_spdx_normalized")
def _license_spdx_normalized(value: Any, ctx: ValidatorContext,
                             params: dict) -> tuple[bool, str]:
    """Every declared license must resolve to SPDX.

    Reads `license_declarations`, so it can say what actually went wrong rather
    than reporting free text as bad expression syntax. `spdx_license_expression`
    checks the flat string and cannot tell the two apart.

    An explicit NOASSERTION passes: the document said it does not know, which is
    what "Explicitly Identifying Unknown Information" asks for. Set
    `allow_declared_unknown: false` in the rule to require a real license.
    """
    declarations = getattr(ctx.target, "license_declarations", None) or []
    if not declarations:
        return True, ""  # absence is `declared`/`present`'s job, not this one
    allow_unknown = params.get("allow_declared_unknown", True)
    problems = []
    for d in declarations:
        if d.resolved:
            continue
        if d.declared_unknown:
            if not allow_unknown:
                problems.append(f"{d.raw!r} is an explicit unknown")
            continue
        if d.ambiguous:
            # A different fix from an unrecognised name: the document names the
            # licence, and the author has to say which identifier they mean.
            problems.append(
                f"{d.raw!r} (declared in the {d.source!r} field) names a licence "
                f"but not an SPDX identifier: it does not say whether later "
                f"versions are permitted, so it could be "
                f"{AMBIGUOUS_NAMES[descriptive_key(d.raw)]}")
            continue
        problems.append(
            f"{d.raw!r} (declared in the {d.source!r} field) does not resolve "
            f"to an SPDX license")
    if problems:
        return False, "; ".join(problems[:3])
    return True, ""


@register("license_in_spdx_field")
def _license_in_spdx_field(value: Any, ctx: ValidatorContext,
                           params: dict) -> tuple[bool, str]:
    """A well-formed SPDX expression must not hide in the free-text slot.

    CycloneDX `license.name` is for text that could not be pinned to SPDX. A
    valid expression there is a generator bug: a consumer reading only
    `expression` and `license.id` misses the license entirely, even though it is
    perfectly well formed.
    """
    declarations = getattr(ctx.target, "license_declarations", None) or []
    misplaced = [d for d in declarations if d.misplaced]
    if misplaced:
        return False, "; ".join(
            f"{d.raw!r} is valid SPDX but was declared in the free-text "
            f"'name' field rather than 'expression'" for d in misplaced[:3])
    return True, ""


@register("purl_wellformed")
def _purl_wellformed(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    from packageurl import PackageURL
    for v in _as_list(value):
        if not v:
            continue
        try:
            PackageURL.from_string(str(v))
        except ValueError:
            return False, f"{v!r} is not a well-formed PURL"
    return True, ""


# NIST IR 7695 Appendix A, transcribed. These are the specification's own regular
# expressions for the two bindings, not a paraphrase of them.
#
# Hand-rolled structural checks kept passing malformed names one class at a time:
# first any `part` value, then empty attributes, then attribute text containing
# spaces. Each fix closed one hole and left the rest, because a component count
# and a part check are not the grammar. These are.
#
# §6.2.2 (formatted string): `part` is a/h/o or the logical values `*` (ANY) and
# `-` (NA); each attribute is either a logical value or printable text whose
# special characters are backslash-escaped; `language` is an RFC 5646 tag.
CPE23_RE = re.compile(
    r'cpe:2\.3:[aho*\-]'
    r'(:(((\?*|\*?)([a-zA-Z0-9\-._]|(\\[\\*?!"#$%&\'()+,/:;<=>@\[\]^`{|}~]))+(\?*|\*?))|[*\-])){5}'
    r'(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[*\-]))'
    r'(:(((\?*|\*?)([a-zA-Z0-9\-._]|(\\[\\*?!"#$%&\'()+,/:;<=>@\[\]^`{|}~]))+(\?*|\*?))|[*\-])){4}'
)

# §6.1 (URI binding): `cpe:/` then up to seven percent-encoded components. The
# scheme is case-insensitive and `part` may be upper case, which an a/h/o-only
# check rejected -- `cpe:/A:vendor:prod` is a valid name.
# One deliberate deviation from the published expression, which reads
# `c[pP][eE]:/`: it pins the first letter to lower case while allowing either
# case for the other two, so `CPE:/a:vendor` is rejected and `cPE:/a:vendor` is
# not. URI schemes are case-insensitive (RFC 3986 §3.1) and the mixed classes
# read as an incomplete attempt to say so, so the scheme matches either case
# here. Rejecting a validly-spelled name would be a false FAIL.
CPE22_RE = re.compile(r'cpe:/[AHOaho]?(:[A-Za-z0-9._\-~%]*){0,6}', re.IGNORECASE)


def _split_unescaped(value: str, delimiter: str = ":") -> list[str]:
    """Split on delimiters that are not escaped, counting backslashes by parity.

    §6.2.2 escapes a special character in an attribute with a backslash, and a
    literal backslash as a pair. So whether a delimiter is data depends on the
    *length* of the backslash run before it: odd escapes it, even does not,
    because those backslashes escape each other. A one-character negative
    lookbehind gets the even case wrong, and Python's `re` cannot express a
    variable-length lookbehind.

    Used for diagnostics rather than validation: the grammar above decides
    well-formedness, and this says how many components the author actually wrote
    when that count is what went wrong.
    """
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == delimiter:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


@register("cpe_wellformed")
def _cpe_wellformed(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    """Both CPE bindings, against the grammar in NIST IR 7695.

    This checks form, not existence: whether the vendor and product name a real
    product is not something an SBOM validator can answer, and a rule that
    pretended otherwise would fail correct documents.
    """
    for v in _as_list(value):
        if not v:
            continue
        s = str(v).strip()
        if s.startswith("cpe:2.3:"):
            if not CPE23_RE.fullmatch(s):
                # The count is the usual mistake, and "found 12" is a more useful
                # thing to be told than "does not match the grammar".
                found = len(_split_unescaped(s))
                if found != 13:
                    return False, (f"{v!r} is not a well-formed CPE 2.3 name: expected 13 "
                                   f"colon-separated components, found {found}")
                return False, (f"{v!r} is not a well-formed CPE 2.3 name "
                               f"(NIST IR 7695 §6.2.2)")
        elif s.lower().startswith("cpe:/"):
            if not CPE22_RE.fullmatch(s):
                return False, (f"{v!r} is not a well-formed CPE 2.2 URI "
                               f"(NIST IR 7695 §6.1)")
        else:
            return False, f"{v!r} is not a CPE name (expected a 'cpe:2.3:' or 'cpe:/' prefix)"
    return True, ""


@register("component_identifier")
def _component_identifier(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    """A purl or a CPE, each validated as what it is.

    Used where a clause accepts either identifier. Pairing a rule's `fields:
    [purl, cpe]` with `purl_wellformed` would reject a CPE for not being a purl,
    so the form is decided per value by its prefix rather than by which attribute
    it was read from.
    """
    for v in _as_list(value):
        if not v:
            continue
        s = str(v).strip()
        # Lower-cased for routing only. `_cpe_wellformed` accepts a
        # case-insensitive scheme for the 2.2 URI, so a case-sensitive test here
        # sent `CPE:/a:vendor:prod` to the "neither" branch and reported it as
        # not an identifier at all, while the validator it never reached would
        # have passed it.
        lowered = s.lower()
        if lowered.startswith("cpe:"):
            ok, msg = _cpe_wellformed(v, ctx, params)
        elif lowered.startswith("pkg:"):
            ok, msg = _purl_wellformed(v, ctx, params)
        else:
            return False, (f"{v!r} is neither a purl (expected a 'pkg:' prefix) "
                           f"nor a CPE name (expected 'cpe:')")
        if not ok:
            return False, msg
    return True, ""


@register("semver_or_calver")
def _semver_or_calver(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    for v in _as_list(value):
        s = str(v).strip()
        if not (SEMVER_RE.match(s) or CALVER_RE.match(s)):
            return False, f"{v!r} is neither SemVer nor CalVer"
    return True, ""


def _norm_alg(name: Any) -> str:
    """An algorithm name reduced to what identifies it.

    The separator is spelled differently by every source: `SHA3-256` in a
    profile, `sha3-256` in CycloneDX, `sha3_256` from SPDX 3.0's
    `hashAlgorithm_sha3_256`. Stripping only the hyphen left the underscore
    form comparing unequal, so a file carrying a valid SHA3-256 digest failed a
    rule that allows SHA3-256.
    """
    return str(name).replace("-", "").replace("_", "").lower()


@register("hash_algorithm_in_set")
def _hash_algorithm_in_set(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    allowed = {_norm_alg(a) for a in params.get("algs", [])}
    hashes = value if isinstance(value, dict) else getattr(ctx.target, "hashes", {}) or {}
    # str() before replace(): a document is free to put anything in an algorithm
    # position, including null, and a validator must answer rather than raise.
    present = {_norm_alg(k) for k in hashes}
    if not present:
        return False, "no hashes present"
    if allowed and not (present & allowed):
        return False, f"no hash in required set {sorted(params.get('algs', []))} (have {sorted(hashes)})"
    return True, ""


# Hex digest length each algorithm must produce. A value of the wrong length for
# its declared algorithm is not a hash of that artifact, whatever else it is.
HASH_HEX_LENGTHS: dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64, "sha384": 96, "sha512": 128,
    "sha3256": 64, "sha3384": 96, "sha3512": 128,
    "blake2b256": 64, "blake2b384": 96, "blake2b512": 128,
    "blake3": 64,
}
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


@register("hash_wellformed")
def _hash_wellformed(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    """Check each digest is hex and the right length for its declared algorithm.

    `hash_algorithm_in_set` only inspects the algorithm names, so a component
    declaring SHA-256 with a value of "zzz" passes it. The CycloneDX JSON schema
    catches non-hex, but its regex accepts any of the valid digest lengths, so a
    SHA-256 carrying a 40-character value is schema-valid and still wrong. SPDX
    has no equivalent constraint at all.

    A truncated or mismatched digest is worse than a missing one: it looks like
    an integrity check while verifying nothing.
    """
    hashes = value if isinstance(value, dict) else getattr(ctx.target, "hashes", {}) or {}
    for alg, digest in hashes.items():
        key = str(alg).replace("-", "").replace("_", "").lower()
        text = str(digest).strip()
        if not text:
            return False, f"{alg}: empty digest"
        if not HEX_RE.match(text):
            return False, f"{alg}: digest is not hexadecimal ({text[:16]!r})"
        expected = HASH_HEX_LENGTHS.get(key)
        if expected is None:
            continue  # unknown algorithm: hash_algorithm_in_set is the gate for that
        if len(text) != expected:
            return False, (f"{alg}: digest is {len(text)} hex chars, "
                           f"expected {expected} for {alg}")
    return True, ""


@register("format_version_at_least")
def _format_version_at_least(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    minimums = params.get("min_versions", {})
    fmt = ctx.sbom.sbom_format
    minimum = minimums.get(fmt)
    if not minimum:
        return True, ""
    have = ctx.sbom.version_tuple
    want = tuple(int(x) for x in re.findall(r"\d+", str(minimum)))
    if have < want:
        return False, f"{fmt} {ctx.sbom.spec_version} is below required minimum {minimum}"
    return True, ""


@register("format_version_not_deprecated")
def _format_version_not_deprecated(value: Any, ctx: ValidatorContext,
                                   params: dict) -> tuple[bool, str]:
    """Fail when the document declares a spec version its own project has retired.

    Distinct from `format_version_at_least`: a floor says "new enough for this
    regulation", this says "not a version the format's maintainers have moved
    on from". A profile can set a floor above every deprecated version and never
    need this; one that accepts a broad range does.

    The deprecated set arrives through params so it stays profile data rather
    than a judgement frozen in code.
    """
    deprecated = params.get("deprecated_versions", {})
    fmt = ctx.sbom.sbom_format
    retired = [str(v) for v in deprecated.get(fmt, [])]
    if not retired:
        return True, ""
    have = str(ctx.sbom.spec_version)
    if have in retired:
        return False, (f"{fmt} {have} is deprecated "
                       f"(retired versions: {', '.join(retired)})")
    return True, ""


@register("references_vex")
def _references_vex(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    blob = ""
    for c in ctx.sbom.components:
        for ref in c.external_refs:
            blob += str(ref).lower()
    blob += str(ctx.sbom.document.raw).lower()
    if "vex" in blob or "vulnerability" in blob:
        return True, ""
    return False, "no VEX / vulnerability reference found"


@register("signed_with_x509")
def _signed_with_x509(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    if ctx.sbom.document.signed:
        return True, ""
    return False, "SBOM is not signed"


@register("dependency_completeness")
def _dependency_completeness(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    refs_in_graph = set(ctx.sbom.dependencies) | {
        t for targets in ctx.sbom.dependencies.values() for t in targets
    }
    if not ctx.sbom.components:
        return True, ""
    if not refs_in_graph:
        return False, "no dependency relationships declared"
    orphaned = [c.identity for c in ctx.sbom.components
                if (c.bom_ref or c.purl) and (c.bom_ref not in refs_in_graph
                                               and c.purl not in refs_in_graph)]
    if orphaned:
        return False, f"{len(orphaned)} component(s) absent from the dependency graph"
    return True, ""


@register("known_unknowns_declared")
def _known_unknowns_declared(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    # A gap that is explicitly NOASSERTION/NONE is acceptable; a silently missing
    # field is not. Here value is a field that, if absent, must be explicit.
    if value is None:
        return False, "silent gap: field missing with no explicit NOASSERTION/NONE"
    return True, ""


@register("declared")
def _declared(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    """Require a value OR an explicit statement that it is unknown.

    This is CISA 2026 "Explicitly Identifying Unknown Information": if the author
    cannot supply a field, they must say so rather than omit it. So NOASSERTION
    passes and silence fails -- the opposite of `present`, which treats an
    explicit null as absence.

    Distinct from `known_unknowns_declared`, which only rejects `None` and so
    lets an empty list through. A component with `licenses: []` said nothing at
    all, which is exactly the silence this rule exists to catch.
    """
    if value is None:
        return False, "silent gap: no value and no explicit NOASSERTION/NONE"
    # Empty containers and empty strings are silence. `_as_list` now unwraps a
    # mapping to its values so `{}` no longer reads as populated, but it still
    # wraps a bare `""` into `[""]`, which is truthy -- so this stays.
    if isinstance(value, (dict, list, tuple, set, str)) and not value:
        return False, "silent gap: no value and no explicit NOASSERTION/NONE"
    if not _as_list(value):
        return False, "silent gap: no value and no explicit NOASSERTION/NONE"
    return True, ""


# ---- plugin escape hatch -----------------------------------------------------

def load_plugins() -> list[str]:
    """Load third-party validators registered under the 'ossbomer.validators'
    entry-point group. Each entry point is a callable taking `register`."""
    loaded: list[str] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover
        return loaded
    try:
        eps = entry_points(group="ossbomer.validators")
    except TypeError:  # < 3.10 signature
        eps = entry_points().get("ossbomer.validators", [])  # type: ignore[attr-defined,arg-type]
    for ep in eps:
        try:
            fn = ep.load()
            fn(register)
            loaded.append(ep.name)
        # Third-party plugin code. Anything it raises -- on import or on
        # registration -- must not take the host process down or stop the
        # remaining plugins from loading, so this is broad and silent by design.
        except Exception:  # noqa: BLE001, S112
            continue
    return loaded
