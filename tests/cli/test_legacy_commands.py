"""The backward-compatible commands (N4), now front-ends over the engine.

The point of these tests is that `ossbomer-conformance` and `ossbomer-oslc` give
the *same answer* as `ossbomer validate`. The removed implementations did not:
the conformance one checked only `metadata.component` -- the root component the
SBOM describes -- so it never read the component inventory, and it exited 0 no
matter what it found.
"""
import json
import os

from click.testing import CliRunner

from ossbomer.cli import cli
from ossbomer.conformance.cli import DEFAULT_PROFILES
from ossbomer.conformance.cli import validate as conformance_cli
from ossbomer.oslc.cli import USE_CASE_PROFILES
from ossbomer.oslc.cli import validate as oslc_cli

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
CDX = os.path.join(FIX, "cyclonedx", "valid", "cdx-1.6.json")


# ---- ossbomer-conformance ----------------------------------------------------

def test_conformance_reports_per_component_findings():
    """The old implementation could not produce these: it never read components[]."""
    result = CliRunner().invoke(conformance_cli, ["--file", CDX])
    assert "components[0]" in result.output


def test_conformance_exit_code_reflects_the_verdict():
    """The old command exited 0 unconditionally, so it could not gate CI."""
    result = CliRunner().invoke(conformance_cli, ["--file", CDX])
    assert result.exit_code == 1


def test_conformance_matches_ossbomer_validate():
    runner = CliRunner()
    legacy = runner.invoke(conformance_cli, ["--file", CDX, "--json-output"])
    unified = runner.invoke(cli, [
        "validate", "--file", CDX, "--format", "json",
        *[arg for p in DEFAULT_PROFILES for arg in ("--profile", p)],
    ])
    assert legacy.exit_code == unified.exit_code
    assert json.loads(legacy.output) == json.loads(unified.output)


def test_conformance_profile_override():
    result = CliRunner().invoke(conformance_cli, [
        "--file", CDX, "--profile", "ntia-min-elements"])
    assert "NTIA Minimum Elements" in result.output
    assert "EU Cyber Resilience Act" not in result.output


def test_conformance_rules_flag_is_rejected_not_ignored():
    """It was silently ignored once already; accepting it now would repeat that."""
    result = CliRunner().invoke(conformance_cli, ["--file", CDX, "--rules", "x.json"])
    assert result.exit_code == 2
    assert "--rules is no longer supported" in result.output
    assert "--profile" in result.output


# ---- ossbomer-oslc -----------------------------------------------------------

def test_oslc_use_case_selects_the_profile():
    runner = CliRunner()
    internal = runner.invoke(oslc_cli, ["--file", CDX, "--use-case", "internal"])
    saas = runner.invoke(oslc_cli, ["--file", CDX, "--use-case", "saas"])
    assert "internal use only" in internal.output
    assert "network service" in saas.output


def test_oslc_every_advertised_use_case_resolves_to_a_real_profile():
    """A --use-case choice that names a missing profile would only fail at runtime."""
    runner = CliRunner()
    catalog = runner.invoke(cli, ["profiles"]).output
    for use_case, profile_id in USE_CASE_PROFILES.items():
        assert profile_id in catalog, f"--use-case {use_case} -> missing {profile_id}"


def test_oslc_matches_ossbomer_validate():
    runner = CliRunner()
    legacy = runner.invoke(oslc_cli, ["--file", CDX, "--use-case", "mobile",
                                      "--json-output"])
    unified = runner.invoke(cli, ["validate", "--file", CDX, "--format", "json",
                                  "--profile", "license-mobile"])
    assert legacy.exit_code == unified.exit_code
    assert json.loads(legacy.output) == json.loads(unified.output)


def test_oslc_license_rules_flag_is_rejected():
    result = CliRunner().invoke(oslc_cli, ["--file", CDX, "--license-rules", "x.json"])
    assert result.exit_code == 2
    assert "--license-rules is no longer supported" in result.output


# ---- ossbomer-schema ---------------------------------------------------------
# argparse rather than click, and it does not run the engine, so its error
# handling is its own. It still has to honour the same exit-code convention.

def _schema_cli():
    """Run the schema CLI in-process and return (exit_code, stdout, stderr)."""
    import contextlib
    import io

    from ossbomer.schema.cli import main

    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            main()
        except SystemExit as exc:
            code = exc.code or 0
    return code, out.getvalue(), err.getvalue()


def test_schema_cli_missing_file_is_a_message_not_a_traceback(monkeypatch):
    monkeypatch.setattr("sys.argv", ["ossbomer-schema", "/nonexistent.json"])
    code, _, err = _schema_cli()
    assert code == 2
    assert err.startswith("Error:")
    assert "Traceback" not in err


def test_schema_cli_format_mismatch_is_an_error_not_a_verdict(monkeypatch):
    """A format assertion that fails means the run was invalid, not the document."""
    monkeypatch.setattr("sys.argv",
                        ["ossbomer-schema", "--format", "spdx-json", CDX])
    code, _, err = _schema_cli()
    assert code == 2
    assert "Format mismatch" in err


def test_schema_cli_valid_document_exits_zero(monkeypatch):
    monkeypatch.setattr("sys.argv", ["ossbomer-schema", CDX])
    code, _, _ = _schema_cli()
    assert code == 0


def test_every_command_uses_two_for_unprocessable(tmp_path, monkeypatch):
    """One convention across the whole CLI surface: 0 ok, 1 verdict, 2 cannot run."""
    junk = tmp_path / "junk.json"
    junk.write_text("not json at all")
    runner = CliRunner()
    assert runner.invoke(conformance_cli, ["--file", str(junk)]).exit_code == 2
    assert runner.invoke(oslc_cli, ["--file", str(junk)]).exit_code == 2
    assert runner.invoke(
        cli, ["validate", "--profile", "ntia-min-elements", "--file", str(junk)]
    ).exit_code == 2
    monkeypatch.setattr("sys.argv", ["ossbomer-schema", str(junk)])
    assert _schema_cli()[0] == 2
