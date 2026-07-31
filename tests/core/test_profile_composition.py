"""Profile composition: extends / excludes and private overlays (R4, R11)."""
import textwrap

import pytest

from ossbomer.core.profile import ProfileError, load_profile


def test_extends_and_excludes(tmp_path):
    overlay = tmp_path / "acme-cra-overlay.yaml"
    overlay.write_text(textwrap.dedent("""
        id: acme-cra-overlay
        name: ACME internal CRA overlay
        extends: [eu-cra-annex-i]
        excludes: [cra-top-level-dependencies]
        rules:
          - id: acme-namespace-tag
            scope: component
            severity: MUST
            category: Provenance
            citation: "Internal ACME Engineering Standard 7.4"
            field: purl
            validators: [present]
    """))

    profile = load_profile("acme-cra-overlay", extra_dirs=[str(tmp_path)])
    rule_ids = {r.id for r in profile.rules}

    # inherited from the public profile without vendoring it
    assert "cra-component-name" in rule_ids
    # excluded public rule is gone
    assert "cra-top-level-dependencies" not in rule_ids
    # private rule added
    assert "acme-namespace-tag" in rule_ids
    # inherited schema minima carried over. 1.3 is what eu-cra-annex-i declares:
    # the Regulation names no spec version, so the floor is ossbomer's support
    # matrix rather than a CRA demand, with deprecated_versions_forbidden doing
    # the "not a retired version" work.
    assert profile.schema.min_versions.get("cyclonedx") == "1.3"


def test_overlay_search_path_env(tmp_path, monkeypatch):
    overlay = tmp_path / "myprofile.yaml"
    overlay.write_text("id: myprofile\nname: Mine\nrules: []\n")
    monkeypatch.setenv("OSSBOMER_PROFILE_PATH", str(tmp_path))
    profile = load_profile("myprofile")
    assert profile.name == "Mine"


def test_child_overrides_parent_rule(tmp_path):
    overlay = tmp_path / "override.yaml"
    overlay.write_text(textwrap.dedent("""
        id: override
        name: Override
        extends: [ntia-min-elements]
        rules:
          - id: ntia-version
            scope: component
            severity: SHOULD
            category: Completeness
            citation: "relaxed"
            field: version
            validators: [present]
    """))
    profile = load_profile("override", extra_dirs=[str(tmp_path)])
    version_rule = next(r for r in profile.rules if r.id == "ntia-version")
    assert version_rule.severity.value == "SHOULD"  # child relaxed the parent's MUST


def test_scoring_weights_are_inherited(tmp_path):
    """A child that omits `scoring` must score like its parent, not like the default.

    Falling back to DEFAULT_WEIGHTS here reads as inheritance but quietly changes
    the composite, so the two are asserted to be distinguishable.
    """
    parent = tmp_path / "acme-parent.yaml"
    parent.write_text(textwrap.dedent("""
        id: acme-parent
        name: ACME parent
        rules: []
        scoring:
          weights:
            Completeness: 0.05
            Accuracy: 0.80
            Consistency: 0.05
            Provenance: 0.05
            Freshness: 0.05
          thresholds:
            version_coverage_min: 0.42
    """))
    child = tmp_path / "acme-child.yaml"
    child.write_text(textwrap.dedent("""
        id: acme-child
        name: ACME child
        extends: [acme-parent]
        rules: []
    """))

    profile = load_profile("acme-child", extra_dirs=[str(tmp_path)])
    assert profile.weights()["Accuracy"] == 0.80
    assert profile.scoring_thresholds["version_coverage_min"] == 0.42


def test_child_scoring_still_wins(tmp_path):
    parent = tmp_path / "acme-parent2.yaml"
    parent.write_text(textwrap.dedent("""
        id: acme-parent2
        name: ACME parent
        rules: []
        scoring:
          weights: {Accuracy: 0.80}
    """))
    child = tmp_path / "acme-child2.yaml"
    child.write_text(textwrap.dedent("""
        id: acme-child2
        name: ACME child
        extends: [acme-parent2]
        rules: []
        scoring:
          weights: {Accuracy: 0.10}
    """))

    profile = load_profile("acme-child2", extra_dirs=[str(tmp_path)])
    assert profile.weights()["Accuracy"] == 0.10


def test_license_rule_expression_is_rejected_not_ignored(tmp_path):
    """`expression` was parsed and never read.

    Overrides are keyed by `spdx_id`, so an expression-only rule was dropped
    entirely -- and in a profile with no engine the license layer then returned no
    findings at all, reporting PASS having checked nothing.
    """
    p = tmp_path / "acme-expr.yaml"
    p.write_text(textwrap.dedent("""
        id: acme-expr
        name: ACME expression override
        rules: []
        license_policy:
          rules:
            - expression: "MIT AND GPL-3.0-only"
              allowed: false
    """))
    with pytest.raises(ProfileError, match="expression"):
        load_profile("acme-expr", extra_dirs=[str(tmp_path)])


def test_license_rule_without_spdx_id_is_rejected(tmp_path):
    p = tmp_path / "acme-noid.yaml"
    p.write_text(textwrap.dedent("""
        id: acme-noid
        name: ACME missing identifier
        rules: []
        license_policy:
          rules:
            - allowed: false
              reason: "no identifier, so this would match nothing"
    """))
    with pytest.raises(ProfileError, match="spdx_id"):
        load_profile("acme-noid", extra_dirs=[str(tmp_path)])


def test_license_rule_with_spdx_id_still_loads(tmp_path):
    p = tmp_path / "acme-ok.yaml"
    p.write_text(textwrap.dedent("""
        id: acme-ok
        name: ACME valid override
        rules: []
        license_policy:
          rules:
            - spdx_id: LGPL-2.1-only
              allowed: true
              reason: "Reviewed 2026-03; dynamically linked only."
    """))
    profile = load_profile("acme-ok", extra_dirs=[str(tmp_path)])
    assert profile.license_rules[0].spdx_id == "LGPL-2.1-only"
    assert profile.license_rules[0].allowed is True
