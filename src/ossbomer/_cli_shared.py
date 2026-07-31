"""Shared plumbing for the console entry points.

`ossbomer validate` and the two backward-compatible commands
(`ossbomer-conformance`, `ossbomer-oslc`) differ only in which profiles they
preselect. The run / render / exit-code path is identical, so it lives here
once. Three separate implementations is precisely how the legacy commands drifted
into reporting different verdicts for the same document.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Iterable

import click

from .core import validators as _validators
from .core.model import Verdict
from .core.runner import run
from .reporters.render import render

# Non-zero exit codes, documented in the README and relied on by CI consumers.
EXIT_FAIL = 1
EXIT_ERROR = 2


def replaced_option(name: str, replacement: str) -> None:
    """Fail an option that no longer exists, pointing at what replaced it.

    Used for the legacy rules-file flags. Their file formats are gone, so
    accepting the flag and ignoring it would silently validate against something
    other than what the caller asked for -- which is the bug that was fixed in
    the first place.
    """
    click.echo(
        f"Error: {name} is no longer supported. Rules now live in profiles; "
        f"use {replacement} instead. See `ossbomer profiles`.",
        err=True,
    )
    sys.exit(EXIT_ERROR)


def run_and_report(sbom_file: str, profiles: Iterable[str],
                   output_format: str = "console",
                   profile_path: str | None = None) -> None:
    """Run the engine over one SBOM, print the report, exit with its verdict.

    Exit codes: 0 when no profile returned FAIL, 1 when one did, 2 when the
    document could not be processed at all.
    """
    _validators.load_plugins()  # activate any third-party validators (R7)
    extra = profile_path.split(os.pathsep) if profile_path else None
    try:
        results = run(sbom_file, list(profiles), extra)
    # Top-level CLI boundary: any failure below becomes a message and exit 2.
    # Users of a validator should never see a traceback for a bad document.
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    click.echo(render(output_format, sbom_file, results))
    if any(r.verdict is Verdict.FAIL for r in results):
        sys.exit(EXIT_FAIL)
