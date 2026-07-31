---
title: Verdicts and exit codes
layout: default
parent: Reference
nav_order: 2
---

# Verdicts and exit codes
{: .no_toc }

How a set of findings becomes one answer, and what the process returns.

1. TOC
{:toc}

## Verdicts

Each profile yields its own verdict, and they are never blended:

| Verdict | Meaning |
| ------- | ------- |
| `PASS` | Nothing above MAY was violated |
| `WARN` | No MUST violations, but a SHOULD rule failed, or a MUST_WHERE_AVAILABLE rule whose field the document does not carry |
| `FAIL` | At least one MUST rule failed, or a MUST_WHERE_AVAILABLE rule failed on a field the document does carry |

`MAY` rules are reported and never change the verdict.

## Why MUST_WHERE_AVAILABLE exists

Some obligations only bite when the data is there. Supplier name is the usual
example: a document that omits it entirely may be incomplete, but a document that
carries a supplier field full of `NOASSERTION` is asserting something false.

Those deserve different answers, so:

- Field absent: WARN. You are missing data.
- Field present but invalid: FAIL. You are stating something wrong.

Collapsing the two would either let bad data pass or make every incomplete
document a hard failure.

## Exit codes

| Exit | Condition |
| ---- | --------- |
| `0` | No profile returned FAIL, so every profile is PASS or WARN |
| `1` | At least one profile returned FAIL |
| `2` | The document could not be parsed, or the invocation was invalid |

Exit 2 is deliberately not exit 1. "Your SBOM does not meet CRA" and "I could not
read your file" are different problems, and a CI gate that treats a typo in a path
as a compliance failure teaches people to ignore it.

## WARN exits 0

That is on purpose: SHOULD-level misses should not break a build by default. If
you want them to, gate on the JSON:

```bash
ossbomer validate --profile ntia-min-elements --file sbom.json --format json > report.json
python -c "
import json, sys
report = json.load(open('report.json'))
sys.exit(1 if any(r['verdict'] != 'PASS' for r in report['results']) else 0)
"
```

The verdicts live under `results`, not at the top level. See the
[CLI reference]({{ site.baseurl }}/reference/cli) for the full JSON shape.

See [Using it in CI]({{ site.baseurl }}/guide/ci).

## Quality score

The score is separate from the verdict and does not feed into it. Five categories,
each 0-100:

| Category | What it looks at |
| -------- | ---------------- |
| Completeness | Version, PURL, hash, and dependency coverage across components |
| Accuracy | Well-formed identifiers, normalized license expressions, no placeholders |
| Consistency | Supplier and naming agreement across the document |
| Provenance | Author, tool, supplier, and signature presence |
| Freshness | Timestamp validity and how current the declared versions are |

A weighted composite combines them, and the weights come from the profile. A
strict profile can lean on Provenance and Accuracy while a permissive one leans on
Completeness, which is why the same document scores differently under different
profiles.

Scores are computed per profile and never averaged across profiles. A good NTIA
score says nothing about CRA readiness, so combining them would only produce a
number that means nothing.

A document can FAIL on one absent MUST field and still score in the eighties. The
verdict answers "did it meet the bar", the score answers "how good is this
document". Both are useful and they are not the same question.
