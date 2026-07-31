"""Orchestrate a validation run: schema gate -> rule engine -> scoring.

The SBOM is parsed and schema-validated once, then each profile is evaluated
independently, producing one :class:`ProfileResult` (verdict + score) per profile.
Results are never blended across profiles (R9). Everything is offline (N2).
"""
from __future__ import annotations

from ossbomer.scoring.scorer import score

from . import engine
from .ir import Sbom
from .model import Category, Finding, ProfileResult, Severity, Verdict
from .parsers import parse_file
from .profile import Profile, ProfileError, load_profile
from .schema_validation import SchemaResult, validate_schema


def _schema_finding(schema: SchemaResult) -> Finding:
    return Finding(
        rule_id="schema-valid", layer="schema", severity=Severity.MUST,
        category=Category.ACCURACY,
        verdict=Verdict.PASS if schema.valid else Verdict.FAIL,
        citation="structural schema validation",
        path="document", value=schema.spec_version,
        message="valid" if schema.valid else "; ".join(schema.errors[:3]) or "invalid",
    )


def run_profile(sbom: Sbom, profile: Profile, schema: SchemaResult) -> ProfileResult:
    # Refuse rather than return a verdict. A withdrawn profile has no rules, and
    # no findings computes to PASS -- so running one would report success for a
    # standard nothing was checked against, which is the exact failure that got
    # it withdrawn.
    if profile.withdrawn:
        raise ProfileError(f"profile {profile.id!r} is withdrawn: {profile.withdrawn}")
    findings: list[Finding] = [_schema_finding(schema)]
    findings.extend(engine.evaluate(sbom, profile))
    verdict = engine.compute_verdict(findings)
    overall, cats = score(sbom, profile.weights(), profile.scoring_thresholds)
    return ProfileResult(
        profile_id=profile.id, profile_name=profile.name, verdict=verdict,
        score=overall, category_scores=cats, findings=findings,
        schema_valid=schema.valid, sources=profile.sources,
    )


def run(sbom_path: str, profile_names: list[str],
        extra_dirs: list[str] | None = None) -> list[ProfileResult]:
    sbom = parse_file(sbom_path)
    schema = validate_schema(sbom_path)
    results: list[ProfileResult] = []
    for name in profile_names:
        profile = load_profile(name, extra_dirs)
        results.append(run_profile(sbom, profile, schema))
    return results
