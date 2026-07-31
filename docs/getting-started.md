---
title: Getting started
layout: default
nav_order: 2
---

# Getting started
{: .no_toc }

Install ossbomer, validate a file, and read the result.

1. TOC
{:toc}

## What you need

Python 3.9 or newer. It is tested on 3.9 through 3.13.

## Install

```bash
pip install "ossbomer[oslc]"
```

The `oslc` extra pulls in [ospac](https://pypi.org/project/ospac/), which
evaluates license policy. Every `license-*` profile needs it. Plain
`pip install ossbomer` works if you only care about schema and conformance.

To work from a checkout instead:

```bash
git clone https://github.com/SemClone/ossbomer
cd ossbomer
pip install ".[oslc]"
```

{: .warning }
Pin `ossbomer>=2` if you are upgrading. The 0.1.4 release on PyPI predates the
profile engine these docs describe, and the per-layer commands it shipped
behave differently.

{: .note }
A profile that asks for ospac when ospac is not installed exits 2 rather than
quietly skipping the license layer. A skipped check that still reports PASS is
worse than no check at all.

## Run it

Point it at a profile and a file:

```bash
ossbomer validate --profile ntia-min-elements --file sbom.json
```

```
============================================================
Profile: NTIA Minimum Elements for an SBOM
Verdict: FAIL (4 MUST violations)
Quality score: 63 / 100
  Completeness: 63
  Accuracy:     41
  Consistency:  75
  Provenance:   68
  Freshness:    70
Top issues:
  1. Freshness: ntia-timestamp — rfc3339_utc: '2010-01-29T18:30:22' lacks a UTC/timezone designator [document]
  2. Completeness: ntia-unique-identifier — present: field is absent or empty [components[0]:glibc@2.11.1]
  3. Completeness: ntia-unique-identifier — present: field is absent or empty [components[2]:Saxon@8.8]
============================================================
```

Reading that:

- **Verdict** is the pass/fail answer. Four MUST-severity rules failed, so it is
  FAIL. See [Verdicts and exit codes]({{ site.baseurl }}/reference/verdicts).
- **Quality score** is separate from the verdict. It grades how good the document
  is across five categories, not whether it met the bar. A document can FAIL on
  one missing MUST field and still score well.
- **Top issues** name the rule that fired, why, and where. The bracketed part is
  the location, so `components[0]:glibc@2.11.1` is the first component.

## Ask more than one question

`--profile` repeats. Each profile is evaluated on its own and prints its own
block:

```bash
ossbomer validate \
  --profile eu-cra-annex-i \
  --profile bsi-tr-03183-v2.1 \
  --file sbom.json
```

Nothing is merged between them. Two profiles disagreeing about the same document
is normal and is the point.

## See what is available

```bash
ossbomer profiles      # the catalog, id and full name
ossbomer validators    # the field validators profiles can call
```

## Machine-readable output

```bash
ossbomer validate --profile ntia-min-elements --file sbom.json --format json
ossbomer validate --profile ntia-min-elements --file sbom.json --format sarif
```

SARIF gives you one run per profile, which GitHub code scanning renders as
annotations. See [Using it in CI]({{ site.baseurl }}/guide/ci).

## Use it as a library

```python
from ossbomer.core.runner import run

for result in run("sbom.json", ["eu-cra-annex-i", "ntia-min-elements"]):
    print(result.profile_id, result.verdict.value, result.score)
```

## Next steps

- [Profiles]({{ site.baseurl }}/guide/profiles) to pick the right one
- [License policy]({{ site.baseurl }}/guide/license-policy) if licenses are your problem
- [Using it in CI]({{ site.baseurl }}/guide/ci) to gate a build
