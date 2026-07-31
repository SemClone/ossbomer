"""Unified CLI (R1) and per-profile independence (R9)."""
import json
import os

from click.testing import CliRunner

from ossbomer.cli import cli

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
SPDX = os.path.join(FIX, "spdx", "valid", "spdx-2.3.json")
CDX = os.path.join(FIX, "cyclonedx", "valid", "cdx-1.6.json")


def test_declared_version_matches_package_metadata():
    """`--version` reads installed metadata, so `__version__` is decorative and
    can drift from pyproject unnoticed. A release bump has to touch both."""
    from importlib.metadata import version as dist_version

    import ossbomer

    assert ossbomer.__version__ == dist_version("ossbomer")


def test_profiles_command_lists_catalog():
    result = CliRunner().invoke(cli, ["profiles"])
    assert result.exit_code == 0
    assert "ntia-min-elements" in result.output
    assert "cisa-2026-min" in result.output
    assert "eu-cra-annex-vii" in result.output


def test_validators_command():
    result = CliRunner().invoke(cli, ["validators"])
    assert result.exit_code == 0
    assert "present" in result.output
    assert "dependency_completeness" in result.output


def test_validate_console_exit_code_on_fail():
    result = CliRunner().invoke(cli, [
        "validate", "--profile", "ntia-min-elements", "--file", SPDX])
    # the 2.3 example is missing PURLs/UTC timestamp -> MUST failures -> exit 1
    assert result.exit_code == 1
    assert "Verdict:" in result.output
    assert "Quality score:" in result.output


def test_validate_json_multi_profile_independent():
    result = CliRunner().invoke(cli, [
        "validate", "--file", CDX, "--format", "json",
        "--profile", "ntia-min-elements", "--profile", "eu-cra-annex-vii"])
    payload = json.loads(result.output)
    assert len(payload["results"]) == 2
    ids = {r["profile"] for r in payload["results"]}
    assert ids == {"ntia-min-elements", "eu-cra-annex-vii"}
    # each result carries its own independent score + categories (never blended)
    for r in payload["results"]:
        assert 0 <= r["score"] <= 100
        assert set(r["categories"]) == {
            "Completeness", "Accuracy", "Consistency", "Provenance", "Freshness"}


def test_validate_sarif_one_run_per_profile():
    result = CliRunner().invoke(cli, [
        "validate", "--file", CDX, "--format", "sarif",
        "--profile", "ntia-min-elements", "--profile", "eu-cra-annex-vii"])
    sarif = json.loads(result.output)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 2
    names = {run["tool"]["driver"]["name"] for run in sarif["runs"]}
    assert names == {"ossbomer:ntia-min-elements", "ossbomer:eu-cra-annex-vii"}
