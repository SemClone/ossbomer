# Contributing to ossbomer

Thank you for considering a contribution! ossbomer validates SBOMs against
regulations and policy, so correctness matters more here than speed — a wrong
verdict is worse than no verdict. Contributions of every size are welcome.

## Code of Conduct

This project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating you are expected to uphold it. Report unacceptable behavior to
[conduct@semcl.one](mailto:conduct@semcl.one).

## Contributor License Agreement

Before a pull request can be merged, you need to sign the CLA. It is handled in
the PR itself — a bot comments with the agreement, and you accept by replying:

> I have read the Contributor License Agreement and I hereby accept the terms.

The CLA grants your contribution under **Apache-2.0**, the project's license.
You only need to do this once.

## How can I contribute?

### Reporting bugs

Search [existing issues](../../issues) first, including closed ones. If you find
a closed issue that matches, open a new one and link to it rather than commenting
on the old one.

A good bug report for ossbomer includes:

* A clear, descriptive title.
* **The SBOM that triggers it**, reduced to the smallest document that still
  reproduces the problem. Redact freely — replace real component names and URLs
  with placeholders as long as the structure is preserved.
* The **format and version** involved (e.g. CycloneDX 1.5 XML, SPDX 2.3 tag-value).
* The **profile(s)** passed via `--profile`.
* The exact command, the output you got, and the output you expected.
* Your OS, Python version, and `ossbomer --version`.

If a rule produced the wrong verdict, say which rule ID and why you believe the
document should have passed or failed — cite the clause in the underlying
standard where you can. That citation is usually the fastest path to a fix.

### Suggesting enhancements

Open an issue describing the current behavior, the behavior you want, and the
use case behind it. For a new **profile**, link the regulation or program text
you want it to encode; for a new **validator**, describe the check and what a
violation looks like in both SPDX and CycloneDX.

### Adding a profile

Profiles are data, not code — this is the most approachable way in. A profile is
one YAML file in `src/ossbomer/profiles/` binding schema minima, conformance
rules, and license policy. It can compose existing profiles with `extends` and
drop inherited rules with `excludes`.

Every rule needs a `severity` (MUST / MUST-where-available / SHOULD / MAY), a
`category` for scoring, and a `citation` pointing at the clause it comes from.
Rules reference normalized IR fields (`field: version`), not format-specific
paths, so one rule covers both SPDX and CycloneDX. Add fixtures under
`tests/fixtures/` that both pass and fail the profile.

## Development setup

```bash
git clone https://github.com/your-username/ossbomer.git
cd ossbomer

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pytest -q
```

Enable the repository git hooks once per clone:

```bash
git config core.hooksPath .githooks
```

They check staged changes and commit messages for hardcoded credentials and
other content that should not be committed.

### Running tests and lint

```bash
pytest -q                        # full suite
pytest tests/core/test_engine.py # a single file
ruff check .                     # lint
mypy src                         # type check
```

## Pull requests

`main` is protected: it takes no direct pushes, and every change lands through a
pull request with green CI.

1. Fork the repo and branch from `main`.
2. Add tests for any behavior you add or change. A bug fix should come with a
   test that fails without it.
3. Update the documentation if you changed the CLI, the profile format, or the
   validator registry.
4. Add a `CHANGELOG.md` entry under `[Unreleased]`.
5. Make sure `pytest -q`, `ruff check .` and `mypy` all pass locally. All three
   are enforced in CI.
6. Open the PR and confirm all status checks pass — the suite runs on Python
   3.9 through 3.13, plus a job that builds the wheel, installs it into a clean
   environment, and smoke-tests the CLI.
7. Sign the CLA when the bot asks.

Reviewers may ask for changes before merging. Please keep a PR to one coherent
change — it makes review faster and history easier to read.

### Commit messages

* Present tense, imperative mood: "Add CycloneDX 1.6 fixture", not "Added" or
  "Adds".
* Keep the first line at 72 characters or less.
* Explain *why* in the body when the reason is not obvious from the diff.
* Reference issues and PRs after the first line.

### Python style

All code follows [PEP 8](https://peps.python.org/pep-0008/), checked with `ruff`
and type-checked with `mypy`. Both are clean, and both are required checks — a
PR that introduces a finding will not merge.

Two things worth knowing before you reach for a rewrite:

* The project supports **Python 3.9**, so `X | None` annotations are only safe
  in modules that carry `from __future__ import annotations`. Every module using
  that syntax has it; keep it that way when adding files.
* `mypy` cannot be pinned to 3.9 (current versions refuse to target below 3.10),
  so it runs against the invoking interpreter. Runtime 3.9 compatibility is
  covered by the test matrix instead.

Where a broad `except Exception` is deliberate — CLI boundaries, the plugin
loader, predicates that must never raise — it carries a `noqa` with the reason.
Add the reason if you add another.

* Use type hints on public functions.
* Docstrings on public functions, classes, and modules.
* Prefer explicit over implicit — especially in validators, where a silent
  fallback can turn into a wrong compliance verdict.
* No mandatory network calls in the core path. Anything that reaches the network
  must be opt-in, so offline validation keeps working.

## Community

* [Issues](../../issues) — bugs and feature requests
* [Discussions](../../discussions) — questions and design conversations

## Recognition

Significant contributions are recognized in [AUTHORS.md](AUTHORS.md).

Thank you for contributing!
