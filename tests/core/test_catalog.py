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
    "ntia-min-elements", "cisa-2025-min", "cisa-2026-min", "eu-cra-annex-vii",
    "bsi-tr-03183-v2.1", "cert-in-v2.0", "openchain-telco-v1.1", "fedramp-sbom",
    "aibom-v0.1",
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


def test_aibom_is_advisory_only():
    """AIBOM v0.1 uses SHOULD rules, so it never hard-FAILs on missing AI fields."""
    (result,) = run(SAMPLE, ["aibom-v0.1"])
    assert result.must_violations == 0
