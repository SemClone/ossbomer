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
from datetime import datetime
from typing import Any, Callable

from .ir import Sbom, is_null_value

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
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


# ---- core validators ---------------------------------------------------------

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


@register("rfc3339_utc")
def _rfc3339_utc(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    for v in _as_list(value):
        s = str(v).strip()
        try:
            # Accept trailing Z (UTC) or explicit offset.
            datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return False, f"{v!r} is not an RFC 3339 timestamp"
        if not (s.endswith("Z") or "+00:00" in s or re.search(r"[+-]\d\d:\d\d$", s)):
            return False, f"{v!r} lacks a UTC/timezone designator"
    return True, ""


@register("spdx_license_expression")
def _spdx_license_expression(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    try:
        from license_expression import get_spdx_licensing
    except ImportError:  # pragma: no cover - dependency always present via parsers
        return True, "license-expression not available; skipped"
    licensing = get_spdx_licensing()
    for v in _as_list(value):
        if not isinstance(v, str) or is_null_value(v):
            continue
        parsed = licensing.validate(v)
        if parsed.errors:
            return False, f"{v!r} is not a valid SPDX license expression"
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


@register("semver_or_calver")
def _semver_or_calver(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    for v in _as_list(value):
        s = str(v).strip()
        if not (SEMVER_RE.match(s) or CALVER_RE.match(s)):
            return False, f"{v!r} is neither SemVer nor CalVer"
    return True, ""


@register("hash_algorithm_in_set")
def _hash_algorithm_in_set(value: Any, ctx: ValidatorContext, params: dict) -> tuple[bool, str]:
    allowed = {a.replace("-", "").lower() for a in params.get("algs", [])}
    hashes = value if isinstance(value, dict) else getattr(ctx.target, "hashes", {}) or {}
    present = {k.replace("-", "").lower() for k in hashes}
    if not present:
        return False, "no hashes present"
    if allowed and not (present & allowed):
        return False, f"no hash in required set {sorted(params.get('algs', []))} (have {sorted(hashes)})"
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
    # Checked before _as_list: that helper wraps a non-sequence in a one-item
    # list, so an empty dict (`hashes: {}`) would come back as `[{}]` and read as
    # populated. Empty containers and empty strings are silence.
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
