"""Backward-compatible `ossbomer-oslc` command (N4).

A thin front-end over the profile engine. `--use-case` now selects the license
profile, so the policy comes from ospac rather than from a bundled allow/deny
table -- see `ossbomer.oslc.policy`.

The former implementation carried its own 400 KB license table and matched
identifiers against it directly. It has been removed: policy belongs in ospac,
and the profile engine is the one path that evaluates it.
"""
import click

from .._cli_shared import replaced_option, run_and_report

# Use case -> the profile that encodes it. Extends the legacy
# internal/distribution pair rather than replacing it, so existing invocations
# keep working and get the two cases the old table could not express.
USE_CASE_PROFILES = {
    "distribution": "license-distribution",
    "internal": "license-internal",
    "mobile": "license-mobile",
    "saas": "license-saas",
}


@click.command()
@click.option("--file", "sbom_file", required=True,
              type=click.Path(exists=True),
              help="Path to SBOM file (JSON or XML format)")
@click.option("--use-case", "use_case", default="distribution",
              type=click.Choice(sorted(USE_CASE_PROFILES)),
              help="Deployment context the licenses are judged against "
                   "(default: distribution).")
@click.option("--profile-path", "profile_path", default=None,
              help="Extra profile dirs for private overlays.")
@click.option("--json-output", is_flag=True, help="Output results in JSON format")
@click.option("--license-rules", "license_file", default=None, hidden=True)
def validate(sbom_file, use_case, profile_path, json_output, license_file):
    """Validate an SBOM's declared licenses against policy for a use case."""
    if license_file is not None:
        replaced_option(
            "--license-rules",
            "--use-case, or a profile with license_policy.policy_path",
        )
    run_and_report(
        sbom_file,
        [USE_CASE_PROFILES[use_case]],
        output_format="json" if json_output else "console",
        profile_path=profile_path,
    )


if __name__ == "__main__":
    validate()
