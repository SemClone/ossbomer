"""The CISA 2026 Minimum Elements profile.

Published 2026-07-29, "updates and replaces" the 2021 NTIA minimum elements.
These tests pin the two things most likely to rot: that all seventeen data
fields from Appendix A are actually covered by a rule, and that the four
elements needing IR support added in 2.1.0 can genuinely pass rather than
being unsatisfiable by construction.
"""
import json
import os

import pytest

from ossbomer.core.parsers import parse_file
from ossbomer.core.profile import load_profile
from ossbomer.core.runner import run

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
CDX_16 = os.path.join(FIX, "cyclonedx", "valid", "cdx-1.6.json")
SPDX_23 = os.path.join(FIX, "spdx", "valid", "spdx-2.3.json")

# Appendix A, Table 1. The profile must have a rule for each.
APPENDIX_A_ELEMENTS = {
    "cisa26-sbom-author": "SBOM Author",
    "cisa26-sbom-author-signature": "SBOM Author Signature",
    "cisa26-sbom-data-format-name": "SBOM Data Format Name",
    "cisa26-sbom-data-format-version": "SBOM Data Format Version",
    "cisa26-sbom-generation-context": "SBOM Generation Context",
    "cisa26-sbom-timestamp": "SBOM Timestamp",
    "cisa26-sbom-tool-name": "SBOM Tool Name",
    "cisa26-sbom-tool-version": "SBOM Tool Version",
    "cisa26-sbom-version": "SBOM Version",
    "cisa26-component-producer": "Component Producer",
    "cisa26-component-dependency-relationship": "Component Dependency Relationship",
    "cisa26-component-hash-value": "Component Hash Value",
    "cisa26-component-hash-algorithm": "Component Hash Algorithm",
    "cisa26-component-identifiers": "Component Identifiers",
    "cisa26-component-license": "Component License",
    "cisa26-component-name": "Component Name",
    "cisa26-component-version": "Component Version",
}


def test_covers_every_appendix_a_element():
    profile = load_profile("cisa-2026-min")
    ids = {r.id for r in profile.rules}
    missing = set(APPENDIX_A_ELEMENTS) - ids
    assert not missing, f"no rule for: {sorted(missing)}"


def test_every_rule_cites_the_2026_document():
    profile = load_profile("cisa-2026-min")
    for rule in profile.rules:
        assert rule.citation.startswith("CISA 2026"), \
            f"{rule.id} cites {rule.citation!r}, not the 2026 document"


def test_does_not_inherit_2021_rule_ids():
    """The 2026 document renames four fields; inheriting NTIA would report the
    old names and old citations under a 2026 conformance claim."""
    profile = load_profile("cisa-2026-min")
    assert not [r for r in profile.rules if r.id.startswith("ntia-")]


def test_sources_name_the_2026_document():
    profile = load_profile("cisa-2026-min")
    assert profile.sources
    assert "2026" in profile.sources[0]["ref"]


def test_runs_and_produces_a_verdict():
    (result,) = run(CDX_16, ["cisa-2026-min"])
    assert result.profile_id == "cisa-2026-min"
    assert 0 <= result.score <= 100
    assert result.verdict.value in {"PASS", "WARN", "FAIL"}


def test_supersession_is_recorded_on_the_older_profiles():
    for pid in ("cisa-2025-min", "ntia-min-elements"):
        profile = load_profile(pid)
        assert "supersed" in profile.name.lower() or "2021" in profile.name, \
            f"{pid} does not flag that it is no longer current"


# ---- the four elements that needed IR support -------------------------------

def _write(tmp_path, data):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _minimal_cdx(**metadata):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 3,
        "metadata": metadata,
        "components": [],
    }


def test_sbom_version_is_parsed_from_cyclonedx(tmp_path):
    sbom = parse_file(_write(tmp_path, _minimal_cdx(timestamp="2026-07-30T00:00:00Z")))
    assert sbom.document.sbom_version == "3"


def test_lifecycles_parsed_from_phase_and_from_name(tmp_path):
    doc = _minimal_cdx(lifecycles=[{"phase": "build"}, {"name": "nightly scan"}])
    sbom = parse_file(_write(tmp_path, doc))
    assert sbom.document.lifecycles == ["build", "nightly scan"]


def test_tool_versions_parsed_from_cyclonedx_1_5_shape(tmp_path):
    doc = _minimal_cdx(tools={"components": [{"name": "syft", "version": "1.4.0"}]})
    sbom = parse_file(_write(tmp_path, doc))
    assert sbom.document.tools == ["syft"]
    assert sbom.document.tool_versions == ["1.4.0"]


def test_tool_versions_parsed_from_legacy_list_shape(tmp_path):
    doc = _minimal_cdx(tools=[{"name": "cdxgen", "version": "9.0.1"}])
    sbom = parse_file(_write(tmp_path, doc))
    assert sbom.document.tools == ["cdxgen"]
    assert sbom.document.tool_versions == ["9.0.1"]


def test_tool_without_a_version_records_no_version(tmp_path):
    """A missing version must stay missing. Inventing one would let an SBOM pass
    SBOM Tool Version while saying nothing about the tool."""
    doc = _minimal_cdx(tools={"components": [{"name": "syft"}]})
    sbom = parse_file(_write(tmp_path, doc))
    assert sbom.document.tools == ["syft"]
    assert sbom.document.tool_versions == []


@pytest.mark.parametrize("rule_id,field", [
    ("cisa26-sbom-version", "sbom_version"),
    ("cisa26-sbom-generation-context", "lifecycles"),
    ("cisa26-sbom-tool-version", "tool_versions"),
])
def test_metadata_rules_pass_when_the_data_is_present(tmp_path, rule_id, field):
    """Guards against a rule pointing at an IR field that no parser populates,
    which would make it permanently unsatisfiable."""
    doc = _minimal_cdx(
        timestamp="2026-07-30T00:00:00Z",
        authors=[{"name": "Example Corp"}],
        lifecycles=[{"phase": "build"}],
        tools={"components": [{"name": "syft", "version": "1.4.0"}]},
    )
    (result,) = run(_write(tmp_path, doc), ["cisa-2026-min"])
    finding = next(f for f in result.findings if f.rule_id == rule_id)
    assert finding.verdict.value == "PASS", f"{rule_id}: {finding.message}"


def test_spdx2_cannot_express_generation_context_so_it_warns():
    """SPDX 2.x has no lifecycle field. The rule is SHOULD precisely so this is
    a warning about the format's limits, not a failure of the document."""
    (result,) = run(SPDX_23, ["cisa-2026-min"])
    finding = next(f for f in result.findings
                   if f.rule_id == "cisa26-sbom-generation-context")
    assert finding.verdict.value == "WARN"
    assert result.must_violations == 0 or finding.severity.value == "SHOULD"


def test_weak_hash_algorithm_is_not_accepted(tmp_path):
    """SHA-1 is off NIST's approved list for integrity. A hash nobody should
    trust must not satisfy Component Hash Algorithm."""
    doc = _minimal_cdx(timestamp="2026-07-30T00:00:00Z")
    doc["components"] = [{
        "type": "library", "name": "left-pad", "version": "1.3.0",
        "purl": "pkg:npm/left-pad@1.3.0",
        "hashes": [{"alg": "SHA-1", "content": "a" * 40}],
    }]
    (result,) = run(_write(tmp_path, doc), ["cisa-2026-min"])
    finding = next(f for f in result.findings
                   if f.rule_id == "cisa26-component-hash-algorithm")
    assert finding.verdict.value != "PASS"


def test_strong_hash_algorithm_is_accepted(tmp_path):
    doc = _minimal_cdx(timestamp="2026-07-30T00:00:00Z")
    doc["components"] = [{
        "type": "library", "name": "left-pad", "version": "1.3.0",
        "purl": "pkg:npm/left-pad@1.3.0",
        "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
    }]
    (result,) = run(_write(tmp_path, doc), ["cisa-2026-min"])
    finding = next(f for f in result.findings
                   if f.rule_id == "cisa26-component-hash-algorithm")
    assert finding.verdict.value == "PASS"
