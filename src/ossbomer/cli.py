"""OSSBomer unified CLI (R1).

    ossbomer validate --profile <name> [--profile <name> ...] --file <sbom>
                      [--format console|json|sarif] [--profile-path DIR]

Each --profile is evaluated independently and produces its own verdict + quality
score block (R9). Everything runs offline (N2). The legacy per-layer CLIs
(ossbomer-schema / -conformance / -oslc) remain available (N4).
"""
from __future__ import annotations

import os

import click

from ossbomer._cli_shared import run_and_report
from ossbomer.core import validators as _validators
from ossbomer.core.profile import list_catalog, load_profile


@click.group()
@click.version_option(package_name="ossbomer")
def cli():
    """OSSBomer: profile-driven SBOM validation, conformance, and license policy."""


@cli.command()
@click.option("--profile", "profiles", multiple=True, required=True,
              help="Profile to validate against (repeatable).")
@click.option("--file", "sbom_file", required=True, type=click.Path(exists=True),
              help="Path to the SBOM file.")
@click.option("--format", "output_format",
              type=click.Choice(["console", "json", "sarif"]), default="console",
              help="Output format (R10).")
@click.option("--profile-path", "profile_path", default=None,
              help=f"Extra profile dirs ({os.pathsep}-separated) for private overlays.")
def validate(profiles, sbom_file, output_format, profile_path):
    """Validate an SBOM against one or more profiles."""
    run_and_report(sbom_file, profiles, output_format, profile_path)


@cli.command(name="profiles")
@click.option("--profile-path", "profile_path", default=None,
              help=f"Extra profile dirs ({os.pathsep}-separated).")
def profiles_cmd(profile_path):
    """List available profiles in the catalog (and any overlay dirs)."""
    extra = profile_path.split(os.pathsep) if profile_path else None
    for pid in list_catalog(extra):
        try:
            p = load_profile(pid, extra)
            click.echo(f"{pid:<28} {p.name}")
        # One unloadable profile -- a malformed overlay, say -- should still be
        # listed by id rather than aborting the whole catalog listing.
        except Exception:  # noqa: BLE001
            click.echo(pid)


@cli.command(name="validators")
def validators_cmd():
    """List available field validators (R7)."""
    _validators.load_plugins()
    for name in _validators.available():
        click.echo(name)


def main():
    cli()


if __name__ == "__main__":
    main()
