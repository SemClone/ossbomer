"""ospac-backed license policy: use cases, expression semantics, failure modes."""
import sys

import pytest

from ossbomer.core.engine import evaluate
from ossbomer.core.ir import Component, Document, Sbom
from ossbomer.core.model import Verdict
from ossbomer.core.profile import LicenseRule, Profile, ProfileError
from ossbomer.oslc import policy as policy_mod
from ossbomer.oslc.policy import LicensePolicy, OspacUnavailable

ospac = pytest.importorskip("ospac", reason="ospac is the optional [oslc] extra")


def _sbom(*licenses):
    comps = [Component(name=f"c{i}", version="1.0", licenses=[lic])
             for i, lic in enumerate(licenses)]
    return Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                document=Document(), components=comps)


def _profile(use_case, rules=None, engine="ospac"):
    return Profile(id=f"t-{use_case}", name="t", license_engine=engine,
                   license_use_case=use_case, license_rules=rules or [])


# ---- use cases ---------------------------------------------------------------
# The whole point of the layer: the same license is not the same answer
# everywhere. Internal use is not distribution, and network use triggers AGPL
# obligations that shipping does not.

def test_gpl_denied_when_distributed_but_allowed_internally():
    assert LicensePolicy(use_case="mobile").decide("GPL-3.0-only").denied is True
    assert LicensePolicy(use_case="internal").decide("GPL-3.0-only").denied is False


def test_agpl_denied_for_a_network_service_but_not_for_a_shipped_app():
    assert LicensePolicy(use_case="saas").decide("AGPL-3.0-only").denied is True
    assert LicensePolicy(use_case="mobile").decide("AGPL-3.0-only").denied is False


def test_permissive_is_approved_everywhere():
    for use_case in ("mobile", "saas", "internal", "commercial"):
        assert LicensePolicy(use_case=use_case).decide("MIT").denied is False


# ---- expression semantics ----------------------------------------------------
# These are correctness, not tidiness. Denying "MIT OR GPL-3.0-only" because of
# the GPL operand would be wrong: the licensee picks.

def test_or_takes_the_least_restrictive_operand():
    p = LicensePolicy(use_case="mobile")
    assert p.decide("GPL-3.0-only").denied is True
    assert p.decide("MIT OR GPL-3.0-only").denied is False


def test_and_takes_the_most_restrictive_operand():
    p = LicensePolicy(use_case="mobile")
    assert p.decide("MIT AND GPL-3.0-only").denied is True


def test_license_with_exception_is_classified_on_the_base_license():
    p = LicensePolicy(use_case="mobile")
    assert p.decide("Apache-2.0 WITH LLVM-exception").denied is False


def test_unparseable_license_still_gets_an_answer():
    """Junk must be reviewable, not crash and not silently pass."""
    d = LicensePolicy(use_case="mobile").decide("NOASSERTION")
    assert d.denied is False
    assert d.needs_review is True


def test_decisions_are_cached_per_expression():
    p = LicensePolicy(use_case="mobile")
    first = p.decide("MIT")
    assert p.decide("MIT") is first


# ---- engine integration ------------------------------------------------------

def test_engine_fails_a_denied_license_and_names_the_component():
    findings = evaluate(_sbom("GPL-3.0-only"), _profile("mobile"))
    denied = [f for f in findings if f.rule_id == "license-policy:GPL-3.0-only"]
    assert denied and denied[0].verdict is Verdict.FAIL
    assert "components[0]" in denied[0].path


def test_engine_warns_rather_than_fails_on_review_actions():
    findings = evaluate(_sbom("NOASSERTION"), _profile("mobile"))
    reviewed = [f for f in findings if f.rule_id.startswith("license-policy:")]
    assert reviewed and reviewed[0].verdict is Verdict.WARN


def test_inline_rule_overrides_the_engine():
    """An adopter can allow what policy denies, without editing the policy."""
    allow_gpl = [LicenseRule(spdx_id="GPL-3.0-only", allowed=True, reason="reviewed")]
    findings = evaluate(_sbom("GPL-3.0-only"), _profile("mobile", rules=allow_gpl))
    assert not [f for f in findings if f.verdict is Verdict.FAIL]
    allowed = [f for f in findings if f.rule_id == "license-allowed:GPL-3.0-only"]
    assert allowed and allowed[0].message == "reviewed"


def test_inline_rules_work_without_the_engine():
    deny = [LicenseRule(spdx_id="MIT", allowed=False, reason="no")]
    findings = evaluate(_sbom("MIT"), _profile("mobile", rules=deny, engine=""))
    denied = [f for f in findings if f.rule_id == "license-denied:MIT"]
    assert denied and denied[0].verdict is Verdict.FAIL


def test_no_policy_at_all_produces_no_license_findings():
    findings = evaluate(_sbom("GPL-3.0-only"), _profile("mobile", engine=""))
    assert not [f for f in findings if f.layer == "oslc"]


def test_unknown_engine_is_rejected():
    with pytest.raises(ProfileError, match="unknown license policy engine"):
        evaluate(_sbom("MIT"), _profile("mobile", engine="rego"))


# ---- the optional dependency -------------------------------------------------

def test_missing_ospac_fails_loudly_and_names_the_profile(monkeypatch):
    """Skipping the layer would report a verdict for a document nobody checked."""
    monkeypatch.setitem(sys.modules, "ospac", None)
    with pytest.raises(OspacUnavailable) as excinfo:
        evaluate(_sbom("MIT"), _profile("mobile"))
    message = str(excinfo.value)
    assert "t-mobile" in message
    assert 'pip install "ossbomer[oslc]"' in message


def test_import_helper_raises_the_typed_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "ospac", None)
    with pytest.raises(OspacUnavailable):
        policy_mod._import_runtime()
