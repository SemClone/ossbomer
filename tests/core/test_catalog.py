"""Every bundled profile must load, compose, and run without error (R3)."""
import os

import pytest

from ossbomer.core.model import Category
from ossbomer.core.profile import list_catalog, load_profile
from ossbomer.core.runner import run

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
SAMPLE = os.path.join(FIX, "cyclonedx", "valid", "cdx-1.6.json")

CATALOG = list_catalog()

EXPECTED_PRESENT = {
    "ntia-min-elements", "cisa-2025-min", "cisa-2026-min", "eu-cra-annex-i",
    "bsi-tr-03183-v2.1", "cert-in-v2.0", "openchain-telco-v1.1", "fedramp-sbom",
    "aibom-v0.1", "omb-m-26-05",
}


def test_catalog_has_expected_profiles():
    assert EXPECTED_PRESENT.issubset(set(CATALOG)), \
        f"missing: {EXPECTED_PRESENT - set(CATALOG)}"


@pytest.mark.parametrize("pid", sorted(EXPECTED_PRESENT))
def test_profile_loads_and_is_well_formed(pid):
    p = load_profile(pid)
    assert p.id == pid
    assert p.rules, f"{pid} has no rules"
    # weights are sane
    total = sum(p.weights().get(c.value, 0) for c in Category)
    assert 0.8 <= total <= 1.2, f"{pid} weights sum to {total}"
    # every rule cites a source (R6)
    for r in p.rules:
        assert r.citation, f"{pid}:{r.id} has no citation"


@pytest.mark.parametrize("pid", sorted(EXPECTED_PRESENT))
def test_profile_runs_against_sample(pid):
    (result,) = run(SAMPLE, [pid])
    assert result.profile_id == pid
    assert 0 <= result.score <= 100
    assert result.verdict.value in {"PASS", "WARN", "FAIL"}


def test_withdrawn_profiles_assert_nothing():
    """A profile found to cite a clause that does not exist is emptied, not
    deleted: an id still in someone's CI must resolve and produce no conformance
    claim, rather than either vanishing or continuing to assert.

    `eu-cra-annex-vii` cited Annex VII §8(a)-(c). Annex VII(8) is one sentence
    with no sub-points and no data fields; it is a disclosure trigger. The
    clause that constrains SBOM content is Annex I Part II(1), now
    `eu-cra-annex-i`.
    """
    withdrawn = load_profile("eu-cra-annex-vii")
    assert withdrawn.rules == []
    assert "WITHDRAWN" in withdrawn.name
    assert withdrawn.withdrawn, "no reason recorded, so nothing can refuse it"


def test_a_withdrawn_profile_refuses_to_run_rather_than_passing():
    """Emptying the rules is not enough. compute_verdict over zero findings is
    PASS, so a profile pulled for citing a clause that does not exist would
    start reporting success for a standard nothing was checked against. Worse
    than the original bug, and in a CI gate it turns red to green on upgrade."""
    import pytest as _pytest

    from ossbomer.core.profile import ProfileError
    with _pytest.raises(ProfileError, match="withdrawn"):
        run(SAMPLE, ["eu-cra-annex-vii"])


def test_cra_profile_cites_the_clause_that_specifies_content():
    profile = load_profile("eu-cra-annex-i")
    assert profile.rules
    for rule in profile.rules:
        assert "Annex I Part II(1)" in rule.citation, \
            f"{rule.id} cites {rule.citation!r}"


def test_cra_profile_claims_nothing_the_regulation_does_not_state():
    """Annex I Part II(1) requires identifying and documenting components and
    covering top-level dependencies. It says nothing about SBOM authorship,
    timestamps, licences or hashes, so no rule here may imply otherwise."""
    profile = load_profile("eu-cra-annex-i")
    fields = {r.field for r in profile.rules if r.field}
    assert not fields & {"creators", "timestamp", "licenses", "hashes"}


def test_aibom_is_advisory_only():
    """AIBOM v0.1 uses SHOULD rules, so it never hard-FAILs on missing AI fields."""
    (result,) = run(SAMPLE, ["aibom-v0.1"])
    assert result.must_violations == 0


def test_documented_profile_count_matches_the_catalog():
    """The count appears in four places and drifted once already. A usable
    profile is one that is not withdrawn."""
    usable = [pid for pid in CATALOG if not load_profile(pid).withdrawn]
    assert len(usable) == 14, f"catalog has {len(usable)} usable profiles; update the docs"
