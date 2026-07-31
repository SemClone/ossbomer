"""Hash quality checks.

From the SBOM-quality checklist these implement: "Verify that all components
include the same set of hashes and that the length and format of these hash
strings correspond to the expected values."

Presence alone was previously enough. A component could declare SHA-256 with a
value of "zzz" and pass every hash rule, which is worse than declaring no hash:
it looks like an integrity check while verifying nothing.
"""
import json

import pytest

from ossbomer.core import validators as V
from ossbomer.core.ir import Component, Sbom
from ossbomer.core.runner import run
from ossbomer.scoring.scorer import gather_signals


def _ctx(hashes):
    sbom = Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                components=[Component(name="x", hashes=hashes)])
    return sbom, V.ValidatorContext(sbom, sbom.components[0], "")


@pytest.mark.parametrize("hashes,ok", [
    ({"sha256": "a" * 64}, True),
    ({"sha512": "b" * 128}, True),
    ({"sha1": "c" * 40}, True),
    ({"md5": "d" * 32}, True),
    ({"sha3-256": "e" * 64}, True),
    ({"blake3": "f" * 64}, True),
    # Non-hex.
    ({"sha256": "zzz"}, False),
    ({"sha256": "not-a-digest-" + "a" * 51}, False),
    # Right shape, wrong length for the declared algorithm. This is the case the
    # CycloneDX schema lets through: 40 hex chars is a valid digest length, just
    # not for SHA-256.
    ({"sha256": "a" * 40}, False),
    ({"sha512": "a" * 64}, False),
    ({"md5": "a" * 64}, False),
    # Empty.
    ({"sha256": ""}, False),
])
def test_digest_must_match_its_declared_algorithm(hashes, ok):
    _, ctx = _ctx(hashes)
    got, msg = V.get("hash_wellformed")(hashes, ctx, {})
    assert got is ok, f"{hashes} -> {got} ({msg})"


def test_unknown_algorithm_is_left_to_the_algorithm_gate():
    """hash_wellformed knows nothing about which algorithms are acceptable; that
    is hash_algorithm_in_set's job. It only refuses digests it can measure."""
    _, ctx = _ctx({"whirlpool": "a" * 128})
    ok, _ = V.get("hash_wellformed")({"whirlpool": "a" * 128}, ctx, {})
    assert ok


def test_algorithm_gate_and_wellformedness_are_independent():
    """A strong algorithm with a broken digest must still fail."""
    _, ctx = _ctx({"sha512": "short"})
    strong, _ = V.get("hash_algorithm_in_set")(
        {"sha512": "short"}, ctx, {"algs": ["SHA-512"]})
    wellformed, _ = V.get("hash_wellformed")({"sha512": "short"}, ctx, {})
    assert strong and not wellformed


# ---- scoring -----------------------------------------------------------------

def _sbom(components):
    return Sbom(sbom_format="cyclonedx", spec_version="1.6", encoding="json",
                components=components)


def test_malformed_hashes_do_not_count_toward_coverage():
    good = _sbom([Component(name="a", hashes={"sha256": "a" * 64})])
    bad = _sbom([Component(name="a", hashes={"sha256": "zzz"})])
    assert gather_signals(good).hash_coverage == 1.0
    assert gather_signals(bad).hash_coverage == 0.0


def test_mixed_algorithms_lower_hash_consistency():
    """"Verify that all components include the same set of hashes." Two
    generators merged without reconciliation shows up here."""
    uniform = _sbom([Component(name=n, hashes={"sha256": "a" * 64})
                     for n in "abcd"])
    mixed = _sbom([Component(name="a", hashes={"sha256": "a" * 64}),
                   Component(name="b", hashes={"sha256": "b" * 64}),
                   Component(name="c", hashes={"sha1": "c" * 40}),
                   Component(name="d", hashes={"md5": "d" * 32})])
    assert gather_signals(uniform).hash_consistency == 1.0
    assert gather_signals(mixed).hash_consistency == 0.5


def test_no_hashes_anywhere_is_not_an_inconsistency():
    """Absent hashes are a completeness problem, reported by the profile rules.
    Scoring them as inconsistent too would penalise the same gap twice."""
    assert gather_signals(_sbom([Component(name="a")])).hash_consistency == 1.0


def test_hash_quality_reaches_the_score(tmp_path):
    """hash_coverage was gathered and then read by no category, so hash quality
    could not affect any score at all."""
    def build(content):
        doc = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"timestamp": "2026-07-30T00:00:00Z",
                         "authors": [{"name": "ACME"}],
                         "lifecycles": [{"phase": "build"}],
                         "tools": {"components": [
                             {"type": "application", "name": "syft", "version": "1.0"}]}},
            "components": [{"type": "library", "name": "left-pad", "version": "1.3.0",
                            "purl": "pkg:npm/left-pad@1.3.0",
                            "supplier": {"name": "ACME"},
                            "licenses": [{"expression": "MIT"}],
                            "hashes": [{"alg": "SHA-256", "content": content}]}],
            "dependencies": [{"ref": "pkg:npm/left-pad@1.3.0", "dependsOn": []}],
        }
        path = tmp_path / f"{content[:6]}.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return str(path)

    (good,) = run(build("a" * 64), ["cisa-2026-min"])
    (bad,) = run(build("a" * 40), ["cisa-2026-min"])
    assert bad.score < good.score
    assert bad.category_scores["Accuracy"] < good.category_scores["Accuracy"]
    assert any(f.rule_id.startswith("cisa26-component-hash") and f.verdict.value == "FAIL"
               for f in bad.findings)
