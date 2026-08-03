"""Rule engine, validators, verdict, and scoring behavior."""
import pytest

from ossbomer.core import validators as V
from ossbomer.core.engine import _run_validators, compute_verdict, evaluate
from ossbomer.core.ir import Component, Document, Sbom
from ossbomer.core.model import Severity, Verdict
from ossbomer.core.profile import LicenseRule, Profile, ProfileError, Rule
from ossbomer.scoring.scorer import score


def _ctx(sbom, target=None):
    return V.ValidatorContext(sbom, target, "")


def _sbom(components, **doc):
    return Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                document=Document(**doc), components=components)


# ---- validators --------------------------------------------------------------

def test_present_rejects_noassertion():
    s = _sbom([])
    assert V.get("present")("NOASSERTION", _ctx(s), {})[0] is False
    assert V.get("present")("left-pad", _ctx(s), {})[0] is True
    assert V.get("present")("", _ctx(s), {})[0] is False


def test_non_placeholder():
    s = _sbom([])
    assert V.get("non_placeholder")("TODO", _ctx(s), {})[0] is False
    assert V.get("non_placeholder")("1.2.3", _ctx(s), {})[0] is True


def test_rfc3339_requires_utc():
    s = _sbom([])
    assert V.get("rfc3339_utc")("2026-01-01T00:00:00Z", _ctx(s), {})[0] is True
    assert V.get("rfc3339_utc")("2010-01-29T18:30:22", _ctx(s), {})[0] is False


# The check used to delegate its grammar to `datetime.fromisoformat`, which
# implements ISO 8601 rather than RFC 3339. It therefore accepted values its own
# message called invalid -- a false PASS, the worst direction for a conformance
# tool -- while rejecting the lower case forms section 5.6 explicitly permits.

@pytest.mark.parametrize("value, reason", [
    ("2026-07-15T10:00:00Z", "canonical"),
    ("2026-07-15T10:00:00+00:00", "explicit UTC offset, as the SPDX parser emits"),
    ("2026-07-15T10:00:00+05:30", "a non-UTC offset is still a designator"),
    ("2020-08-03T01:28:52.765Z", "fractional seconds"),
    ("2026-01-01T00:00:00.5Z", "fractional seconds of any length"),
    ("2026-01-01t00:00:00z", "lower case t and z, section 5.6"),
    ("2026-01-01 00:00:00+00:00", "space for T, the section 5.6 note"),
    ("2016-12-31T23:59:60Z", "leap second, section 5.7"),
    ("2016-12-31T18:59:60-05:00", "the same leap second seen from -05:00"),
    ("2017-01-01T05:29:60+05:30", "same leap second, offset moves the date"),
    ("2026-06-30T23:59:60Z", "a leap second may end any month, not only December"),
])
def test_rfc3339_accepts(value, reason):
    assert V.get("rfc3339_utc")(value, _ctx(_sbom([])), {})[0] is True, reason


@pytest.mark.parametrize("value, reason", [
    ("2010-01-29T18:30:22", "no offset"),
    ("2026-01-01+00:00", "a date is not a date-time"),
    ("2026-01-01T00:00+00:00", "partial-time requires seconds"),
    ("2026-01-01T00:00:00+00:00:00", "time-numoffset is exactly +-HH:MM"),
    ("2026-02-30T00:00:00Z", "no such day"),
    ("2026-01-01T25:00:00Z", "no such hour"),
    ("2026-01-01T00:00:61Z", "no such second, 60 being the leap second"),
    ("2026-01-01T00:00:60Z", "60 is not a free 61st second of any minute"),
    ("2026-01-01T12:30:60Z", "a leap second does not fall mid-day"),
    ("2026-01-01T23:59:60Z", "the last minute of a day that does not end a month"),
    ("2016-12-31T23:59:60+01:00", "that offset puts the leap second at 22:59 UTC"),
    ("٢٠٢٦-٠١-٠١T٠٠:٠٠:٠٠Z", "ABNF DIGIT is ASCII"),
    ("9999-12-31T23:59:60Z", "the last representable day has no day after it"),
    ("0001-01-01T00:29:60+00:30", "nor the first one a day before"),
    ("2026-01-01T00:00:00+99:00", "no such offset"),
    ("not-a-timestamp", "not a timestamp at all"),
])
def test_rfc3339_rejects(value, reason):
    assert V.get("rfc3339_utc")(value, _ctx(_sbom([])), {})[0] is False, reason


def test_rfc3339_names_a_missing_offset_specifically():
    """The docs quote this message, and it is the one users actually hit."""
    ok, msg = V.get("rfc3339_utc")("2010-01-29T18:30:22", _ctx(_sbom([])), {})
    assert ok is False
    assert msg == "'2010-01-29T18:30:22' lacks a UTC/timezone designator"


def test_purl_wellformed():
    s = _sbom([])
    assert V.get("purl_wellformed")("pkg:npm/left-pad@1.3.0", _ctx(s), {})[0] is True
    assert V.get("purl_wellformed")("not a purl", _ctx(s), {})[0] is False


def test_semver_or_calver():
    s = _sbom([])
    assert V.get("semver_or_calver")("1.2.3", _ctx(s), {})[0] is True
    assert V.get("semver_or_calver")("2024.03", _ctx(s), {})[0] is True
    assert V.get("semver_or_calver")("banana", _ctx(s), {})[0] is False


def test_spdx_license_expression():
    s = _sbom([])
    assert V.get("spdx_license_expression")("MIT OR Apache-2.0", _ctx(s), {})[0] is True
    assert V.get("spdx_license_expression")("Apache2-ish", _ctx(s), {})[0] is False


def test_hash_algorithm_in_set():
    comp = Component(name="x", hashes={"sha256": "a" * 64})
    s = _sbom([comp])
    ctx = _ctx(s, comp)
    assert V.get("hash_algorithm_in_set")(comp.hashes, ctx, {"algs": ["SHA-256"]})[0] is True
    assert V.get("hash_algorithm_in_set")(comp.hashes, ctx, {"algs": ["SHA-512"]})[0] is False


# ---- engine ------------------------------------------------------------------

def test_must_fails_verdict():
    s = _sbom([Component(name="x", version=None)])
    profile = Profile(id="t", name="t", rules=[
        Rule(id="r-version", scope="component", severity=Severity.MUST,
             category=None, validators=["present"], field="version"),
    ])
    findings = evaluate(s, profile)
    # includes the component version finding
    version_findings = [f for f in findings if f.rule_id == "r-version"]
    assert version_findings and version_findings[0].verdict is Verdict.FAIL
    assert compute_verdict(findings) is Verdict.FAIL


def test_must_where_available_absent_is_warn_not_fail():
    s = _sbom([Component(name="x", supplier=None)])
    profile = Profile(id="t", name="t", rules=[
        Rule(id="r-supplier", scope="component", severity=Severity.MUST_WHERE_AVAILABLE,
             category=None, validators=["present"], field="supplier"),
    ])
    findings = [f for f in evaluate(s, profile) if f.rule_id == "r-supplier"]
    assert findings[0].verdict is Verdict.WARN  # absent -> not available -> WARN


def test_should_is_warn_only():
    s = _sbom([Component(name="x", purl=None)])
    profile = Profile(id="t", name="t", rules=[
        Rule(id="r-purl", scope="component", severity=Severity.SHOULD,
             category=None, validators=["present"], field="purl"),
    ])
    findings = evaluate(s, profile)
    assert compute_verdict(findings) is Verdict.WARN


def test_license_policy_denies():
    comp = Component(name="x", licenses=["GPL-3.0-only"])
    s = _sbom([comp])
    profile = Profile(id="t", name="t", license_rules=[
        LicenseRule(spdx_id="GPL-3.0-only", allowed=False, reason="copyleft"),
    ])
    findings = evaluate(s, profile)
    denied = [f for f in findings if f.rule_id.startswith("license-denied")]
    assert denied and denied[0].verdict is Verdict.FAIL


# ---- scoring -----------------------------------------------------------------

def test_score_bounds_and_categories():
    comp = Component(name="left-pad", version="1.3.0", purl="pkg:npm/left-pad@1.3.0",
                     licenses=["MIT"], hashes={"sha256": "a" * 64}, supplier="ACME")
    s = _sbom([comp], timestamp="2026-01-01T00:00:00Z", tools=["ossbomer"], supplier="ACME")
    s.dependencies = {"root": ["pkg:npm/left-pad@1.3.0"]}
    overall, cats = score(s, Profile.DEFAULT_WEIGHTS, {})
    assert 0 <= overall <= 100
    assert set(cats) == {"Completeness", "Accuracy", "Consistency", "Provenance", "Freshness"}
    assert cats["Completeness"] > 50  # well-populated component


def test_score_penalizes_empty_sbom():
    s = _sbom([Component(name="x")])  # no version/purl/license/hash
    overall, _ = score(s, Profile.DEFAULT_WEIGHTS, {})
    good = _sbom([Component(name="x", version="1.0.0", purl="pkg:npm/x@1.0.0",
                            licenses=["MIT"], hashes={"sha256": "a" * 64})])
    good_overall, _ = score(good, Profile.DEFAULT_WEIGHTS, {})
    assert good_overall > overall


# ---- malformed validator specs -----------------------------------------------

def test_validator_spec_without_a_name_names_the_offending_spec():
    """A dict spec missing 'name' used to reach V.get(None).

    That surfaced as "Unknown validator: None", which tells the profile author
    nothing about which rule is broken. Profiles are hand-written YAML, so the
    error has to identify the spec.
    """
    s = _sbom([])
    with pytest.raises(ProfileError, match=r"no 'name'"):
        _run_validators("value", _ctx(s), [{"min_versions": {"spdx": "2.2"}}])


def test_unknown_validator_name_still_raises():
    s = _sbom([])
    with pytest.raises(KeyError, match="Unknown validator"):
        _run_validators("value", _ctx(s), ["no_such_validator"])


def test_non_dict_non_str_specs_are_skipped():
    s = _sbom([])
    assert _run_validators("value", _ctx(s), [None, 42]) == (True, "")


# ---- deprecated spec versions ------------------------------------------------
# This knob existed in the profile format and was parsed and then ignored, while
# two shipped profiles declared it. These pin that it now does something.

def _schema_profile(**schema_kwargs):
    from ossbomer.core.profile import SchemaPolicy
    return Profile(id="t", name="t", schema=SchemaPolicy(**schema_kwargs))


def _cdx(version):
    return Sbom(sbom_format="cyclonedx", spec_version=version, encoding="json",
                document=Document(), components=[])


def test_deprecated_version_fails_when_the_profile_forbids_it():
    findings = evaluate(_cdx("1.1"), _schema_profile(deprecated_versions_forbidden=True))
    f = [x for x in findings if x.rule_id == "schema-version-not-deprecated"]
    assert f and f[0].verdict is Verdict.FAIL
    assert "deprecated" in f[0].message


def test_current_version_passes():
    findings = evaluate(_cdx("1.6"), _schema_profile(deprecated_versions_forbidden=True))
    f = [x for x in findings if x.rule_id == "schema-version-not-deprecated"]
    assert f and f[0].verdict is Verdict.PASS


def test_nothing_is_checked_unless_the_profile_asks():
    findings = evaluate(_cdx("1.1"), _schema_profile())
    assert not [x for x in findings if x.rule_id == "schema-version-not-deprecated"]


def test_profile_can_override_the_deprecated_set():
    """The list is data, not a judgement frozen in the engine."""
    profile = _schema_profile(deprecated_versions_forbidden=True,
                              deprecated_versions={"cyclonedx": ["1.6"]})
    findings = evaluate(_cdx("1.6"), profile)
    f = [x for x in findings if x.rule_id == "schema-version-not-deprecated"]
    assert f and f[0].verdict is Verdict.FAIL
    # ...and the default no longer applies once overridden.
    findings = evaluate(_cdx("1.1"), profile)
    f = [x for x in findings if x.rule_id == "schema-version-not-deprecated"]
    assert f and f[0].verdict is Verdict.PASS


def test_the_two_shipped_profiles_that_declare_it_actually_enforce_it():
    from ossbomer.core.profile import load_profile
    for pid in ("eu-cra-annex-i", "bsi-tr-03183-v2.1"):
        profile = load_profile(pid)
        assert profile.schema.deprecated_versions_forbidden is True
        findings = evaluate(_cdx("1.1"), profile)
        f = [x for x in findings if x.rule_id == "schema-version-not-deprecated"]
        assert f and f[0].verdict is Verdict.FAIL, pid


def test_the_default_list_covers_versions_that_actually_parse():
    """A deprecated-version rule is only worth having where documents reach it.

    SPDX 2.1 and CycloneDX 1.2 parse, so the rule decides them. CycloneDX 1.0/1.1
    are rejected by the parser first, so they can never be judged here -- they
    stay listed defensively, not because they fire.
    """
    from ossbomer.core.profile import DEFAULT_DEPRECATED_VERSIONS
    profile = _schema_profile(deprecated_versions_forbidden=True)

    reachable = [
        Sbom(sbom_format="spdx", spec_version="2.1", encoding="json",
             document=Document(), components=[]),
        _cdx("1.2"),
    ]
    for sbom in reachable:
        f = [x for x in evaluate(sbom, profile)
             if x.rule_id == "schema-version-not-deprecated"]
        assert f and f[0].verdict is Verdict.FAIL, sbom.spec_version

    assert "1.2" in DEFAULT_DEPRECATED_VERSIONS["cyclonedx"]
    assert "2.1" in DEFAULT_DEPRECATED_VERSIONS["spdx"]


def test_license_validator_survives_a_parser_that_raises():
    """Real SBOMs carry licence strings that make license-expression raise
    rather than report. "MIT (http://mootools.net/license.txt)" appears in the
    ProtonMail SBOM and trips an AttributeError inside the library.

    Six profiles crashed with exit 2 on that document. A validator must return
    a verdict, not take the run down: a value the parser cannot handle is not a
    valid SPDX expression, which is a finding, not a crash.
    """
    from ossbomer.core import validators as V
    from ossbomer.core.ir import Component, Sbom

    nasty = "MIT (http://mootools.net/license.txt)"
    sbom = Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                components=[Component(name="mootools", licenses=[nasty])])
    ctx = V.ValidatorContext(sbom, sbom.components[0], "")
    ok, msg = V.get("spdx_license_expression")([nasty], ctx, {})
    assert ok is False
    assert "mootools" in msg
