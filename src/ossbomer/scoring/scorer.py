"""Quality scoring (R9, §6).

Emits five orthogonal category scores (0-100) plus a weighted composite. Weights
come from the profile, so a strict profile can weight Provenance/Accuracy heavily
while a permissive one weights Completeness. Scores are computed per profile and
are never blended across profiles (that mixing happens nowhere in the codebase).
"""
from __future__ import annotations

from dataclasses import dataclass

from ossbomer.core import validators as V
from ossbomer.core.ir import Sbom, is_null_value
from ossbomer.core.model import Category

# Derived from the Category enum rather than restated, so the scoring vocabulary
# cannot drift from the one findings are tagged with.
CATEGORIES = [c.value for c in Category]


def _ratio(numer: int, denom: int) -> float:
    return (numer / denom) if denom else 1.0


@dataclass
class Signals:
    version_coverage: float
    purl_coverage: float
    hash_coverage: float
    noassertion_density: float
    license_normalization: float
    dependency_completeness: float
    supplier_consistency: float
    has_tool: bool
    has_supplier: bool
    signed: bool
    references_vex: bool
    timestamp_ok: bool
    version_current: float


def _spdx_expr_ok(expr: str) -> bool:
    try:
        from license_expression import get_spdx_licensing
        return not get_spdx_licensing().validate(expr).errors
    # A scoring predicate must never raise: an unparseable expression, or a
    # missing optional dependency, simply scores as not-ok.
    except Exception:  # noqa: BLE001
        return False


def gather_signals(sbom: Sbom) -> Signals:
    comps = sbom.components
    n = len(comps)

    version_ok = sum(1 for c in comps if c.version and not is_null_value(c.version))
    purl_ok = 0
    for c in comps:
        if c.purl:
            try:
                from packageurl import PackageURL
                PackageURL.from_string(c.purl)
                purl_ok += 1
            except ValueError:
                pass
    hash_ok = sum(1 for c in comps if c.hashes)

    # NOASSERTION density across the three most consequential fields.
    total_fields = 0
    null_fields = 0
    for c in comps:
        for val in (c.version, c.supplier, "; ".join(c.licenses) if c.licenses else None):
            total_fields += 1
            if val is None or (isinstance(val, str) and is_null_value(val)):
                null_fields += 1

    lic_total = sum(len(c.licenses) for c in comps)
    lic_norm = sum(1 for c in comps for lic in c.licenses
                   if not is_null_value(lic) and _spdx_expr_ok(lic))

    # dependency completeness (reuse the validator's logic)
    ctx = V.ValidatorContext(sbom, sbom, "dependencies")
    dep_ok, _ = V.get("dependency_completeness")(None, ctx, {})

    # supplier consistency: same purl should map to one supplier string
    by_purl: dict[str, set] = {}
    for c in comps:
        if c.purl:
            by_purl.setdefault(c.purl, set()).add(c.supplier or "")
    inconsistent = sum(1 for s in by_purl.values() if len(s) > 1)
    supplier_consistency = 1.0 - _ratio(inconsistent, len(by_purl)) if by_purl else 1.0

    ts_ctx = V.ValidatorContext(sbom, sbom.document, "document.timestamp")
    ts_ok, _ = V.get("rfc3339_utc")(sbom.document.timestamp, ts_ctx, {}) \
        if sbom.document.timestamp else (False, "")

    vex_ok, _ = V.get("references_vex")(None, V.ValidatorContext(sbom, sbom, ""), {})

    return Signals(
        version_coverage=_ratio(version_ok, n),
        purl_coverage=_ratio(purl_ok, n),
        hash_coverage=_ratio(hash_ok, n),
        noassertion_density=_ratio(null_fields, total_fields),
        license_normalization=_ratio(lic_norm, lic_total),
        dependency_completeness=1.0 if dep_ok else 0.0,
        supplier_consistency=supplier_consistency,
        has_tool=bool(sbom.document.tools or sbom.document.creators),
        has_supplier=bool(sbom.document.supplier) or any(c.supplier for c in comps),
        signed=sbom.document.signed,
        references_vex=vex_ok,
        timestamp_ok=bool(ts_ok),
        version_current=_version_currency(sbom),
    )


def _version_currency(sbom: Sbom) -> float:
    vt = sbom.version_tuple
    if sbom.sbom_format == "cyclonedx":
        if vt >= (1, 5):
            return 1.0
        if vt >= (1, 4):
            return 0.7
        return 0.4
    if sbom.sbom_format == "spdx":
        if vt >= (3, 0):
            return 1.0
        if vt >= (2, 3):
            return 0.9
        if vt >= (2, 2):
            return 0.6
        return 0.3
    return 0.5


def _mean(*xs: float) -> float:
    xs = tuple(x for x in xs if x is not None)
    return sum(xs) / len(xs) if xs else 0.0


def category_scores(sig: Signals) -> dict[str, int]:
    completeness = _mean(sig.version_coverage, sig.purl_coverage, 1.0 - sig.noassertion_density)
    accuracy = _mean(sig.license_normalization, sig.purl_coverage, 1.0 if sig.timestamp_ok else 0.4)
    consistency = _mean(sig.supplier_consistency, sig.license_normalization)
    provenance = _mean(
        1.0 if sig.has_tool else 0.0,
        1.0 if sig.has_supplier else 0.0,
        1.0 if sig.signed else 0.3,
        1.0 if sig.references_vex else 0.4,
    )
    freshness = _mean(sig.version_current, 1.0 if sig.timestamp_ok else 0.5)
    return {
        Category.COMPLETENESS.value: round(completeness * 100),
        Category.ACCURACY.value: round(accuracy * 100),
        Category.CONSISTENCY.value: round(consistency * 100),
        Category.PROVENANCE.value: round(provenance * 100),
        Category.FRESHNESS.value: round(freshness * 100),
    }


def score(sbom: Sbom, weights: dict[str, float], thresholds: dict[str, float] | None = None
          ) -> tuple[int, dict[str, int]]:
    """Return (overall_composite_0_100, per_category_scores)."""
    sig = gather_signals(sbom)
    cats = category_scores(sig)

    # Apply profile thresholds as penalties on the relevant category.
    thresholds = thresholds or {}
    if "noassertion_density_max" in thresholds and \
            sig.noassertion_density > thresholds["noassertion_density_max"]:
        cats["Completeness"] = max(0, cats["Completeness"] - 15)
    if "version_coverage_min" in thresholds and \
            sig.version_coverage < thresholds["version_coverage_min"]:
        cats["Completeness"] = max(0, cats["Completeness"] - 15)
    if "license_normalization_min" in thresholds and \
            sig.license_normalization < thresholds["license_normalization_min"]:
        cats["Accuracy"] = max(0, cats["Accuracy"] - 15)

    total_w = sum(weights.get(c, 0.0) for c in CATEGORIES) or 1.0
    composite = sum(cats[c] * weights.get(c, 0.0) for c in CATEGORIES) / total_w
    return round(composite), cats
