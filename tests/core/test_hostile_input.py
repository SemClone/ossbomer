"""Validators must answer, not raise, whatever a field contains.

An SBOM field carries whatever the generator put there. Real documents contain
free text where an identifier belongs, nulls where strings belong, and values
that make third-party parsers fail in their own error handlers.

The motivating case: `slick@1.12.2` in the ProtonMail SBOM declares its licence
as `"MIT (http://mootools.net/license.txt)"`. The parentheses make
license-expression raise `AttributeError` inside its own error handler, and six
profiles exited 2 on that one field.

Two layers are tested here. Individual validators should handle hostile values
themselves, and the engine should convert anything that still escapes into a
finding rather than letting it end the run. The second layer matters because
third parties register validators through the `ossbomer.validators` entry point,
so not all code in that loop is auditable from this repository.
"""
import json

import pytest

from ossbomer.core import validators as V
from ossbomer.core.ir import Component, Document, Sbom
from ossbomer.core.model import Verdict
from ossbomer.core.profile import Profile, ProfileError, Rule
from ossbomer.core.runner import run

# Values a real generator, a hand edit, or a hostile actor might leave behind.
HOSTILE = [
    None, "", "   ", 0, 1, -1, 3.14, True, [], {}, set(),
    "MIT (http://mootools.net/license.txt)",
    "(((", ")))", "AND", "OR", "WITH", "MIT AND", "MIT OR OR MIT",
    "\x00\x01\x02", "\ud800", "𝕏" * 50, "a" * 10_000,
    "../../etc/passwd", "<script>alert(1)</script>", "'; DROP TABLE--",
    {"a": object()}, [object()], object(),
    {"sha256": None}, {"sha256": object()}, {None: "x"}, {"": ""},
    ["MIT", None, 42], b"bytes", bytearray(b"x"),
    float("nan"), float("inf"), 10**100,
]

PARAMS = {
    "hash_algorithm_in_set": {"algs": ["SHA-256"]},
    "format_regex": {"pattern": r"^\d+$"},
    "format_version_at_least": {"min_versions": {"cyclonedx": "1.5"}},
    "format_version_not_deprecated": {"deprecated_versions": {"cyclonedx": ["1.2"]}},
}


def _ctx():
    sbom = Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                document=Document(), components=[Component(name="x")])
    return V.ValidatorContext(sbom, sbom.components[0], "")


@pytest.mark.parametrize("name", V.available())
def test_no_validator_raises_on_hostile_input(name):
    fn, params, ctx = V.get(name), PARAMS.get(name, {}), _ctx()
    for value in HOSTILE:
        try:
            ok, msg = fn(value, ctx, params)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"{name} raised {type(exc).__name__} on {value!r}: {exc}")
        assert isinstance(ok, bool), f"{name} returned a non-bool for {value!r}"
        assert isinstance(msg, str), f"{name} returned a non-str message for {value!r}"


def test_engine_turns_a_raising_validator_into_a_finding(request):
    """The safety net for validators this repository does not own.

    Third parties register their own through the `ossbomer.validators` entry
    point, so a run can execute code that was never reviewed here.
    """
    from ossbomer.core.engine import evaluate
    from ossbomer.core.model import Severity

    @V.register("_explodes_for_test")
    def _boom(value, ctx, params):
        raise RuntimeError("upstream parser fell over")

    # The registry is process-wide, so leaving this behind changes what other
    # tests see from V.available().
    request.addfinalizer(lambda: V._REGISTRY.pop("_explodes_for_test", None))

    sbom = Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                components=[Component(name="x", version="1.0")])
    profile = Profile(id="t", name="t", rules=[
        Rule(id="r", scope="component", severity=Severity.MUST, category=None,
             validators=["_explodes_for_test"], field="name")])

    findings = evaluate(sbom, profile)

    (finding,) = [f for f in findings if f.rule_id == "r"]
    assert finding.verdict is Verdict.FAIL
    assert "could not evaluate" in finding.message
    assert "RuntimeError" in finding.message


def test_a_malformed_profile_still_fails_loudly():
    """The engine swallows bad data, not bad configuration. A profile naming a
    validator that does not exist is the operator's problem and must not be
    reported as if the document were at fault."""
    from ossbomer.core.engine import evaluate
    from ossbomer.core.model import Severity

    sbom = Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                components=[Component(name="x")])
    profile = Profile(id="t", name="t", rules=[
        Rule(id="r", scope="component", severity=Severity.MUST, category=None,
             validators=[{"no_name_key": True}], field="name")])
    with pytest.raises(ProfileError):
        evaluate(sbom, profile)


def test_a_document_full_of_junk_still_produces_a_verdict(tmp_path):
    """End to end: every field replaced with something hostile. The run must
    finish and report, because reporting is the entire job."""
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "not-a-timestamp",
                     "authors": [{"name": ""}],
                     "lifecycles": [{"phase": None}],
                     "tools": {"components": [{"type": "application", "name": None}]}},
        "components": [
            {"type": "library", "name": "MIT (http://mootools.net/license.txt)",
             "version": "(((", "purl": "not a purl",
             "supplier": {"name": None},
             "licenses": [{"license": {"name": "MIT (http://mootools.net/license.txt)"}},
                          {"expression": "((("}],
             "hashes": [{"alg": "SHA-256", "content": "zzz"},
                        {"alg": "NOT-AN-ALG", "content": None}]},
        ],
        "dependencies": [],
    }
    path = tmp_path / "junk.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    for pid in ("cisa-2026-min", "ntia-min-elements", "license-distribution"):
        (result,) = run(str(path), [pid])
        assert result.verdict in {Verdict.PASS, Verdict.WARN, Verdict.FAIL}
        assert 0 <= result.score <= 100
        assert result.findings


@pytest.mark.parametrize("timestamp", [
    "9999-12-31T23:59:60Z",
    "0001-01-01T00:29:60+00:30",
])
def test_a_leap_second_at_the_edge_of_the_calendar_still_reports(tmp_path, timestamp):
    """`rfc3339_utc` steps to the following day to ask whether a leap second
    ends its month, and the first and last representable dates have no
    neighbour to step to. The scorer calls the validator directly, outside the
    engine's guard, so an OverflowError there ended the whole run instead of
    failing one rule.
    """
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": timestamp,
                     "component": {"type": "application", "bom-ref": "root",
                                   "name": "app", "version": "1.0.0"}},
        "components": [{"type": "library", "bom-ref": "a", "name": "liba",
                        "version": "1.0.0"}],
        "dependencies": [{"ref": "root", "dependsOn": ["a"]}],
    }
    path = tmp_path / "edge.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    (result,) = run(str(path), ["ntia-min-elements"])
    assert result.verdict in {Verdict.PASS, Verdict.WARN, Verdict.FAIL}
    assert 0 <= result.score <= 100


def test_an_unknown_validator_name_is_not_treated_as_bad_data():
    """The guard covers the invocation, not the lookup. A profile naming a
    validator that does not exist is a typo in the profile, and reporting it as
    a finding would blame the document for the operator's mistake."""
    from ossbomer.core.engine import evaluate
    from ossbomer.core.model import Severity

    sbom = Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                components=[Component(name="x")])
    profile = Profile(id="t", name="t", rules=[
        Rule(id="r", scope="component", severity=Severity.MUST, category=None,
             validators=["no_such_validator"], field="name")])
    with pytest.raises(KeyError, match="Unknown validator"):
        evaluate(sbom, profile)
