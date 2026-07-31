---
title: License policy
layout: default
parent: Guide
nav_order: 3
---

# License policy
{: .no_toc }

One question per declared license: given how you ship this, does policy allow it?

1. TOC
{:toc}

## Everything is normalized to SPDX first

Policy is keyed on SPDX identifiers, so a declaration has to reach SPDX or be
reported as not reaching it. An SBOM states a license in whichever slot its
generator reached for, and ecosystems invented their own operators along the way.
All of this normalizes:

| Declared | Normalized | How |
| -------- | ---------- | --- |
| `mit`, `apache-2.0` | `MIT`, `Apache-2.0` | SPDX parse |
| `GPL-2.0+` | `GPL-2.0-or-later` | SPDX parse |
| `MIT or Apache-2.0` | `MIT OR Apache-2.0` | SPDX parse |
| `Apache-2.0 with LLVM-exception` | `Apache-2.0 WITH LLVM-exception` | SPDX parse |
| `MIT \|\| Apache-2.0` | `MIT OR Apache-2.0` | npm's documented OR |
| `MIT/Apache-2.0`, `MIT, Apache-2.0` | `MIT AND Apache-2.0` | separator, read conservatively |
| `Apache 2`, `Apache2` | `Apache-2.0` | curated alias |

A bare list does not say whether both licenses apply or either does. Policy takes
the least restrictive operand of an `OR` and the most restrictive of an `AND`, so
reading a list as `OR` when it meant `AND` under-reports obligations and can pass
something that should have been denied. Lists are therefore read as `AND`, which
over-reports and surfaces for review instead.

### What is deliberately not resolved

`BSD`, `GPL`, `LGPL`, `Apache`, `Public Domain`, `BSD-like`, `see LICENSE file`.

Family names do not name a license. `BSD` is 2-clause or 3-clause and the choice
changes obligations; `GPL` states neither version nor only/or-later. Resolving
them would produce a confident answer the document does not support.

`GPL` is a special case worth knowing about: the underlying parser *will* resolve
it, to `GPL-1.0-or-later`, because that is what the deprecated bare key meant.
Nobody writing `GPL` in an SBOM today means version 1.0, so it is refused
explicitly.

Unresolved text still reaches policy verbatim, because a policy may list the
exact string and "unknown" is a reviewable answer. It is reported as unresolved
either way.

### Extending the tables

License spellings drift, and you know your own suppliers' habits better than any
shipped table does. Point `OSSBOMER_LICENSE_ALIASES` at one or more files
(`os.pathsep`-separated):

```yaml
# acme-licenses.yaml
aliases:
  "acme proprietary v2": LicenseRef-ACME-2.0
  "BSD-like": BSD-3-Clause        # you accept the risk on this one
never_resolve:
  - "internal"                     # never let this look like a license
separators:
  " plus ": " AND "
```

```bash
OSSBOMER_LICENSE_ALIASES=./acme-licenses.yaml \
  ossbomer validate --profile cisa-2026-min --file sbom.json
```

Overlays are applied after the built-ins and win on conflict, so a shipped
mapping you disagree with can be overridden in either direction. Packages can
also register an `ossbomer.license_aliases` entry point, the same way validators
extend.

## What this does not answer

The question is "does policy allow the license this SBOM **declares**". It is not
"is the declared license **correct**".

That boundary is deliberate. Deciding whether a component is really MIT means
reading the component's source or binary, and this tool reads one document. An
SBOM that declares MIT for a GPL-3.0 library will pass a `license-*` profile,
because the policy engine was asked about MIT and MIT is what it was told.

So a PASS here means the declared licenses are acceptable for your distribution
model. It does not mean the declarations are true. If the SBOM came from a
scanner you do not control, the declarations carry that scanner's confidence, not
this tool's.

Verifying declarations against the actual code is a different job, done by
license detection tools rather than by a document validator. ossbomer does not
attempt it and does not pretend to.

## Why the use case decides

The same license is not the same answer everywhere, so a tool that answers
"is GPL-3.0 allowed?" without knowing how you ship is guessing:

```bash
ossbomer validate --profile license-internal --file sbom.json   # GPL: fine
ossbomer validate --profile license-mobile   --file sbom.json   # GPL: denied
ossbomer validate --profile license-saas     --file sbom.json   # GPL and AGPL: denied
```

Internal use is not distribution, so most copyleft obligations never trigger.
Running a network service does trigger AGPL source disclosure, which shipping a
binary does not. App store terms conflict with GPL-3.0 in ways that a server
deployment never encounters.

## Where the rules live

The rules are in [ospac](https://pypi.org/project/ospac/), not in ossbomer. That
separation is deliberate: you change the answer by pointing at a different policy
directory, not by patching the tool or waiting on a release.

```yaml
license_policy:
  engine: ospac            # omit to use only the inline rules below
  use_case: mobile         # passed to ospac as `distribution_type`
  policy_path: ./policies  # optional: your own ospac policy dir, relative to this file
  context:                 # optional: any other keys your policy matches on
    linking_type: dynamic_linking
  rules:                   # optional: overrides for specific identifiers
    - spdx_id: LGPL-2.1-only
      allowed: true
      reason: "Reviewed 2026-03; dynamically linked only."
```

The engine runs first, then inline `rules` override it. So you can allow something
your policy denies, or deny something it allows, without forking the policy. Give
a `reason` when you do; it shows up in the report and saves the next person from
re-deriving your decision.

Inline rules work on their own. Drop `engine` and you have a small policy with no
optional dependency at all.

{: .note }
An override needs a `spdx_id`, and it must be one SPDX identifier rather than an
expression. Overrides are matched by exact identifier, so an expression would match
nothing; both an `expression` key and a missing `spdx_id` are rejected when the
profile loads rather than sitting there doing nothing. To decide on expressions,
let the engine evaluate them — see below.

## SPDX expressions

Declared licenses are frequently expressions, not single identifiers, and getting
the operators wrong produces wrong compliance answers:

| Declared | Result | Why |
| -------- | ------ | --- |
| `MIT OR GPL-3.0-only` | allowed | You pick the operand, so the least restrictive one governs |
| `MIT AND GPL-3.0-only` | denied for distribution | Every operand applies, so the most restrictive governs |
| `Apache-2.0 WITH LLVM-exception` | allowed | Classified on the base license |

## When ospac is missing

A profile declaring `engine: ospac` without ospac installed exits 2 instead of
skipping the layer:

```bash
pip install ".[oslc]"
```

{: .warning }
This is intentional. A license check that silently does nothing and still reports
PASS is worse than no check at all, because someone will ship on the strength of
it.

## What is not here yet

Package and PURL level risk is a separate concern and is still pending. The old
136 MB bundled advisory dataset and `PackageRiskAnalyzer` were removed. Risk will
come back through the open PURL API as an opt-in network feature, so the default
stays offline.
