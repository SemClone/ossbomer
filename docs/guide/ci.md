---
title: Using it in CI
layout: default
parent: Guide
nav_order: 5
---

# Using it in CI
{: .no_toc }

The exit code is designed to be the gate, so most setups are one step.

1. TOC
{:toc}

## The simple gate

```yaml
- name: Check the SBOM
  run: |
    pip install "ossbomer[oslc]"
    ossbomer validate --profile eu-cra-annex-vii --file sbom.json
```

Exit 0 means no profile came back FAIL. Exit 1 means at least one did. Exit 2
means the document could not be parsed or the invocation was wrong, which you want
to fail loudly rather than treat as a compliance result.

## Deciding how strict to be

By default WARN exits 0, so SHOULD-level misses do not break the build. If you
want them to, gate on the JSON instead of the exit code:

```bash
ossbomer validate --profile ntia-min-elements --file sbom.json --format json > report.json
python -c "
import json, sys
report = json.load(open('report.json'))
if any(r['verdict'] != 'PASS' for r in report['results']):
    sys.exit(1)
"
```

Note the verdicts are under `results`; the top level is an object carrying the
document path alongside them, not a bare list.

Full table in [Verdicts and exit codes]({{ site.baseurl }}/reference/verdicts).

## SARIF and code scanning

SARIF output produces one run per profile, which GitHub renders as inline
annotations on the pull request:

```yaml
- name: Check the SBOM
  run: ossbomer validate --profile eu-cra-annex-vii --file sbom.json --format sarif > ossbomer.sarif
  continue-on-error: true

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ossbomer.sarif
```

`continue-on-error` matters here. Without it a FAIL stops the job before the
upload step, and you lose the annotations that explain why it failed.

## Several obligations at once

One invocation, one report, separate verdicts:

```bash
ossbomer validate \
  --profile eu-cra-annex-vii \
  --profile ntia-min-elements \
  --profile license-distribution \
  --file sbom.json \
  --format sarif > ossbomer.sarif
```

The job fails if any of them fails. Because the runs stay separate in the SARIF,
the annotations still tell you which obligation was the problem.

## Notes for build environments

Nothing calls the network, so this works on isolated runners with no allowlisting.

Pin the version you gate on. A profile gaining a rule is a behavior change from
your build's point of view, and finding that out from a red build on an unrelated
pull request is nobody's good afternoon.

Install the `oslc` extra whenever a `license-*` profile is in the list, or the run
exits 2.
