"""Rule engine: evaluate a profile against an SBOM IR (R5-R8).

Produces a list of :class:`Finding` objects and an overall :class:`Verdict`,
iterating per component and per dependency. Severity semantics:

    MUST                  failure -> FAIL (blocks the verdict)
    MUST_WHERE_AVAILABLE  failure only counts when the data is present; a silent
                          absence is reported as WARN, not FAIL
    SHOULD                failure -> WARN
    MAY                   advisory; never changes the verdict
"""
from __future__ import annotations

from typing import Any

from ..oslc.policy import LicensePolicy, OspacUnavailable
from . import validators as V
from .ir import Sbom
from .model import Category, Finding, Severity, Verdict
from .profile import Profile, ProfileError, Rule


def _has_value(value: Any) -> bool:
    """Whether `value` is something a validator could act on.

    Delegates to the validator layer so this and `present` cannot answer the
    question differently -- they already have, twice. See
    :func:`ossbomer.core.validators.has_value`.
    """
    return V.has_value(value)


def _extract_any(target: Any, fields: list[str]) -> Any:
    """First of `fields` that carries a real value, else the last one's value.

    A requirement satisfiable in more than one way needs the value that actually
    satisfied it, not whichever attribute happens to be listed first. Falling
    back to the last lookup rather than to None keeps the "absent" case reporting
    a value in the same shape a single-field rule would, which is what
    `data_available` and the finding's `value` are read from downstream.
    """
    value = None
    for name in fields:
        value = _extract(target, name)
        if _has_value(value):
            return value
    return value


def _extract(target: Any, field: str | None) -> Any:
    if field is None:
        return None
    if hasattr(target, field):
        return getattr(target, field)
    raw = getattr(target, "raw", None)
    if isinstance(raw, dict):
        cur: Any = raw
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur
    return None


def _run_validators(value: Any, ctx: V.ValidatorContext, specs: list[Any]) -> tuple[bool, str]:
    for spec in specs:
        if isinstance(spec, str):
            name, params = spec, {}
        elif isinstance(spec, dict):
            declared = spec.get("name")
            # Previously this reached V.get(None) and surfaced as "Unknown
            # validator: None", which says nothing about which rule is malformed.
            # A profile is hand-written data, so name the offending spec.
            if not isinstance(declared, str):
                raise ProfileError(f"validator spec has no 'name': {spec!r}")
            name = declared
            params = {k: v for k, v in spec.items() if k != "name"}
        else:
            continue
        # A validator must answer, not raise. SBOM fields carry whatever the
        # generator put there, and third parties register their own validators
        # through the `ossbomer.validators` entry point, so the code in this
        # loop is not all auditable from here.
        #
        # A crash here previously took down the entire run: six profiles exited
        # 2 on a real document because one component declared its licence as
        # "MIT (http://mootools.net/license.txt)" and license-expression raised
        # inside its own error handler. One malformed field in one component
        # should cost that component a finding, not the whole report.
        #
        # The lookup stays outside the guard on purpose. A profile naming a
        # validator that does not exist is a configuration error, and reporting
        # it as a finding would blame the document for the operator's typo.
        validator = V.get(name)
        # ProfileError likewise propagates: it means the profile is malformed.
        try:
            ok, msg = validator(value, ctx, params)
        except ProfileError:
            raise
        except Exception as exc:  # noqa: BLE001
            return False, (f"{name}: validator could not evaluate this value "
                           f"({type(exc).__name__}: {exc})")
        if not ok:
            return False, f"{name}: {msg}"
    return True, ""


def _verdict_for(severity: Severity, data_available: bool) -> Verdict:
    if severity is Severity.MUST:
        return Verdict.FAIL
    if severity is Severity.MUST_WHERE_AVAILABLE:
        return Verdict.FAIL if data_available else Verdict.WARN
    if severity is Severity.SHOULD:
        return Verdict.WARN
    return Verdict.WARN  # MAY -> advisory (excluded from verdict aggregation below)


def _eval_rule(sbom: Sbom, rule: Rule) -> list[Finding]:
    findings: list[Finding] = []

    def evaluate_target(target: Any, path: str) -> None:
        value = _extract_any(target, rule.lookup_fields())
        ctx = V.ValidatorContext(sbom, target, path)
        ok, msg = _run_validators(value, ctx, rule.validators)
        if ok:
            findings.append(Finding(rule.id, rule.layer, rule.severity, rule.category,
                                    Verdict.PASS, rule.citation, path, value, "ok"))
            return
        # `_has_value`, not an inline null test: MUST_WHERE_AVAILABLE turns on
        # this flag, so "available" here has to mean what `present` means. An
        # inline `value is not None` counted an empty container as data, which
        # made a rule on `hashes` or `licenses` report FAIL for a component that
        # simply never declared one -- the case the severity exists to excuse.
        data_available = _has_value(value)
        findings.append(Finding(
            rule.id, rule.layer, rule.severity, rule.category,
            _verdict_for(rule.severity, data_available), rule.citation, path, value, msg))

    if rule.scope == "document":
        evaluate_target(sbom.document, "document")
    elif rule.scope == "component":
        if not sbom.components:
            findings.append(Finding(rule.id, rule.layer, rule.severity, rule.category,
                                    Verdict.WARN, rule.citation, "components", None,
                                    "no components in SBOM"))
        for i, comp in enumerate(sbom.components):
            evaluate_target(comp, f"components[{i}]:{comp.identity}")
    elif rule.scope == "file":
        # Two different absences, and only one of them is a defect.
        #
        # A document with no file inventory has broken nothing: SPDX 2.3 §8 makes
        # the section optional and a dependency-level SBOM legitimately has none.
        # A file entry that exists and carries no checksum has broken §8.4, which
        # makes FileChecksum mandatory on an entry that is there.
        #
        # So the inventory's absence is reported WARN whatever the rule's
        # severity, exactly as an SBOM with no components is. Deriving it from
        # the severity instead would make a `MUST` file rule fail every SBOM that
        # simply does not enumerate files, which is the requirement inverted.
        # Within an entry the severity governs as usual, so `MUST` still fails a
        # file whose checksum is missing.
        #
        # WARN rather than silence: nothing was checked, and a rule that emitted
        # no finding at all would be indistinguishable from one that checked and
        # was satisfied.
        if not sbom.files:
            findings.append(Finding(
                rule.id, rule.layer, rule.severity, rule.category,
                Verdict.WARN, rule.citation, "files", None,
                "no file inventory in SBOM"))
        for i, entry in enumerate(sbom.files):
            evaluate_target(entry, f"files[{i}]:{entry.identity}")
    elif rule.scope == "dependency":
        # Graph-level checks operate on the whole SBOM via the validator context.
        evaluate_target(sbom, "dependencies")
    return findings


def _schema_policy_findings(sbom: Sbom, profile: Profile) -> list[Finding]:
    findings: list[Finding] = []
    sp = profile.schema
    if sp.min_versions:
        ctx = V.ValidatorContext(sbom, sbom, "document.specVersion")
        ok, msg = V.get("format_version_at_least")(None, ctx, {"min_versions": sp.min_versions})
        findings.append(Finding(
            "schema-min-version", "schema", Severity.MUST, Category.FRESHNESS,
            Verdict.PASS if ok else Verdict.FAIL, "profile.schema.min_versions",
            "document.specVersion", sbom.spec_version, "ok" if ok else msg))
    if sp.deprecated_versions_forbidden:
        ctx = V.ValidatorContext(sbom, sbom, "document.specVersion")
        ok, msg = V.get("format_version_not_deprecated")(
            None, ctx, {"deprecated_versions": sp.retired_versions()})
        findings.append(Finding(
            "schema-version-not-deprecated", "schema", Severity.MUST,
            Category.FRESHNESS,
            Verdict.PASS if ok else Verdict.FAIL,
            "profile.schema.deprecated_versions_forbidden",
            "document.specVersion", sbom.spec_version, "ok" if ok else msg))
    if sp.require_signature:
        signed = sbom.document.signed
        findings.append(Finding(
            "schema-require-signature", "schema", Severity.MUST, Category.PROVENANCE,
            Verdict.PASS if signed else Verdict.FAIL, "profile.schema.require_signature",
            "document.signature", signed, "ok" if signed else "SBOM is not signed"))
    return findings


def _license_findings(sbom: Sbom, profile: Profile) -> list[Finding]:
    """Evaluate every declared license against the profile's license policy.

    Two layers, in order. The ospac engine decides by use case when the profile
    opts into it, then the profile's inline `license_rules` override that
    decision for specific identifiers -- so an adopter can allow something their
    policy engine denies, or the reverse, without editing the policy itself.
    """
    engine = (profile.license_engine or "").strip().lower()
    if engine and engine != "ospac":
        raise ProfileError(
            f"unknown license policy engine {profile.license_engine!r} "
            f"in profile {profile.id!r} (supported: 'ospac')")

    # `spdx_id` is required and non-empty at parse time, so no filtering here.
    overrides = {r.spdx_id: r for r in profile.license_rules}
    if not engine and not overrides:
        return []

    policy = None
    if engine == "ospac":
        # Deliberately not caught: a profile that asked for policy evaluation and
        # cannot get it must fail, not quietly return a verdict for a document
        # whose licenses were never checked.
        try:
            policy = LicensePolicy(
                use_case=profile.license_use_case,
                policy_path=profile.license_policy_path,
                context=profile.license_context,
            )
        except OspacUnavailable as exc:
            raise OspacUnavailable(f"profile {profile.id!r}: {exc}") from exc

    citation = f"license policy ({profile.license_use_case})"
    findings: list[Finding] = []
    for i, comp in enumerate(sbom.components):
        location = f"components[{i}]:{comp.identity}"
        for lic in comp.licenses:
            override = overrides.get(lic)
            if override is not None:
                verdict = Verdict.PASS if override.allowed else Verdict.FAIL
                reason = override.reason or (
                    f"license {lic} allowed for {profile.license_use_case}"
                    if override.allowed else
                    f"license {lic} not allowed for {profile.license_use_case}")
                findings.append(Finding(
                    f"license-denied:{lic}" if not override.allowed
                    else f"license-allowed:{lic}",
                    "oslc", Severity.MUST, Category.ACCURACY, verdict,
                    citation, location, lic, reason))
                continue

            if policy is None:
                continue

            decision = policy.decide(lic)
            if decision.denied:
                severity, verdict = Severity.MUST, Verdict.FAIL
            elif decision.needs_review:
                severity, verdict = Severity.SHOULD, Verdict.WARN
            else:
                severity, verdict = Severity.MUST, Verdict.PASS

            message = decision.message or (
                f"policy says {decision.action.replace('_', ' ')} "
                f"for use case {profile.license_use_case!r}")
            if decision.remediation and verdict is not Verdict.PASS:
                message = f"{message}. {decision.remediation}"

            findings.append(Finding(
                f"license-policy:{lic}", "oslc", severity, Category.ACCURACY,
                verdict, citation, location, lic, message))
    return findings


def evaluate(sbom: Sbom, profile: Profile) -> list[Finding]:
    """Evaluate all layers of a profile against the SBOM, returning findings."""
    findings: list[Finding] = []
    findings.extend(_schema_policy_findings(sbom, profile))
    for rule in profile.rules:
        findings.extend(_eval_rule(sbom, rule))
    findings.extend(_license_findings(sbom, profile))
    return findings


def compute_verdict(findings: list[Finding]) -> Verdict:
    """FAIL if any MUST/MWA(available) fails; WARN if any SHOULD/MWA fails; else PASS.
    MAY findings never change the verdict."""
    has_fail = False
    has_warn = False
    for f in findings:
        if f.severity is Severity.MAY:
            continue
        if f.verdict is Verdict.FAIL:
            has_fail = True
        elif f.verdict is Verdict.WARN:
            has_warn = True
    if has_fail:
        return Verdict.FAIL
    if has_warn:
        return Verdict.WARN
    return Verdict.PASS
