"""Regression tests for citations that were found to name the wrong clause.

Each assertion below corresponds to a section that was read in the published
document and found not to say what a profile claimed. The source documents, with
checksums, are listed in docs/sources/.

These cannot prove a citation is right. They pin the specific wrong ones so they
cannot come back.
"""
import pytest

from ossbomer.core.profile import list_catalog, load_profile

# (profile id, substring that must NOT appear in any citation, why)
DISPROVEN = [
    ("eu-cra-annex-i", "Annex VII",
     ("Annex VII(8) is one sentence naming no data field; it is a disclosure "
      "trigger. Annex I Part II(1) is the clause that constrains SBOM content.")),
    ("bsi-tr-03183-v2.1", "§6.1",
     ("TR-03183-2 §6.1 is 'Licence identifiers and expressions'. Required data "
      "fields for the SBOM itself are §5.2.1.")),
    ("bsi-tr-03183-v2.1", "§6.2",
     "§6 has no subsection 6.2. Required component fields are §5.2.2."),
    ("bsi-tr-03183-v2.1", "§7",
     "§7 is 'Transitional system', not verification or signing."),
    ("openchain-telco-v1.1", "§4",
     ("§4 of the Telco Guide is 'Conformant notice'. The required SPDX elements "
      "are §3.2.")),
    ("cert-in-v2.0", "§5",
     "CERT-In v2.0 minimum elements are §4.1 Table 5 and §4.2 Data Fields."),
    ("cert-in-v2.0", "§6",
     "Same: §4.1 / §4.2, not §6."),
]


@pytest.mark.parametrize("pid,forbidden,why", DISPROVEN,
                         ids=[f"{p}-{f}" for p, f, _ in DISPROVEN])
def test_no_rule_cites_a_disproven_clause(pid, forbidden, why):
    profile = load_profile(pid)
    offenders = [r.id for r in profile.rules if forbidden in (r.citation or "")]
    assert not offenders, f"{offenders} cite {forbidden!r}. {why}"


def test_bsi_does_not_gate_on_a_signature_it_never_requires():
    """TR-03183-2 mentions signing once, in Appendix 8.1.15: "Ideally, SBOMs
    should be digitally signed." Advisory prose in the explanations appendix is
    not a schema gate, and require_signature would FAIL every unsigned SBOM
    against a requirement BSI did not make."""
    profile = load_profile("bsi-tr-03183-v2.1")
    assert profile.schema.require_signature is False
    signed = [r for r in profile.rules if r.id == "bsi-signed"]
    assert signed and signed[0].severity.value == "SHOULD"


def test_telco_purl_is_not_mandatory():
    """The Guide says "A package SHOULD be identified by a Package URL (PURL)".
    The REQUIRED identifier in 3.2 is SPDXID."""
    profile = load_profile("openchain-telco-v1.1")
    (rule,) = [r for r in profile.rules if r.id == "telco-component-identifier"]
    assert rule.severity.value == "SHOULD"


def test_ntia_supplier_is_mandatory():
    """The 2021 report lists seven data fields flat. None is marked optional or
    conditional, so none may be encoded as merely where-available."""
    profile = load_profile("ntia-min-elements")
    (rule,) = [r for r in profile.rules if r.id == "ntia-supplier"]
    assert rule.severity.value == "MUST"


def test_every_profile_names_a_source():
    """A rule without a traceable source is an assertion the tool cannot defend.
    Withdrawn profiles are exempt only because they assert nothing."""
    for pid in list_catalog():
        profile = load_profile(pid)
        if not profile.rules:
            continue
        assert profile.sources, f"{pid} has rules but names no source document"
        for source in profile.sources:
            assert source.get("ref"), f"{pid} has a source with no ref"


def test_fedramp_invents_no_requirement_of_its_own():
    """FedRAMP publishes no SBOM data field list. EO 14028 §4(e)(vii) requires an
    SBOM and §4(f) delegates the field list to Commerce/NTIA, whose document CISA
    now maintains. So the profile composes and adds nothing: a `fedramp-` rule id
    would name a clause that does not exist."""
    profile = load_profile("fedramp-sbom")
    assert profile.rules, "composition resolved to nothing"
    invented = [r.id for r in profile.rules if r.id.startswith("fedramp-")]
    assert not invented, f"{invented} imply a FedRAMP clause that was never published"
    for rule in profile.rules:
        assert rule.citation.startswith("CISA 2026"), \
            f"{rule.id} cites {rule.citation!r} rather than the inherited source"


def test_fedramp_names_the_delegation_chain():
    """The sources have to show why CISA's fields apply to a FedRAMP package,
    otherwise the inheritance looks arbitrary."""
    refs = " ".join(s.get("ref", "") for s in load_profile("fedramp-sbom").sources)
    assert "14028" in refs and "4(f)" in refs
