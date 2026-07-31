"""Backward-compatible `ossbomer-conformance` command (N4).

A thin front-end over the profile engine. It preselects the profiles that
correspond to what the standalone package used to check, and is otherwise
`ossbomer validate`.

The former implementation kept its own rule table and checked only
`metadata.component` -- the root component the SBOM describes -- so it never
looked at the component inventory, reported conformance a document did not have,
and exited 0 regardless of the result. It has been removed rather than fixed:
one engine, extended through profiles, is the point.
"""
import click

from .._cli_shared import replaced_option, run_and_report

# What the legacy command claimed to check, expressed as profiles.
DEFAULT_PROFILES = ("ntia-min-elements", "eu-cra-annex-vii")


@click.command()
@click.option("--file", "sbom_file", required=True,
              type=click.Path(exists=True),
              help="Path to SBOM file (JSON or XML)")
@click.option("--profile", "profiles", multiple=True,
              help=f"Profile to validate against (repeatable). "
                   f"Default: {', '.join(DEFAULT_PROFILES)}.")
@click.option("--profile-path", "profile_path", default=None,
              help="Extra profile dirs for private overlays.")
@click.option("--json-output", is_flag=True, help="Output results in JSON format")
@click.option("--rules", "rules_file", default=None, hidden=True)
def validate(sbom_file, profiles, profile_path, json_output, rules_file):
    """Validate an SBOM against conformance profiles."""
    if rules_file is not None:
        replaced_option("--rules", "--profile / --profile-path")
    run_and_report(
        sbom_file,
        profiles or DEFAULT_PROFILES,
        output_format="json" if json_output else "console",
        profile_path=profile_path,
    )


if __name__ == "__main__":
    validate()
