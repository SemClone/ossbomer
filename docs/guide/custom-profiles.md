---
title: Writing your own profile
layout: default
parent: Guide
nav_order: 2
---

# Writing your own profile
{: .no_toc }

Profiles are YAML data, not code. Writing one needs no Python and no fork.

1. TOC
{:toc}

## How a profile is evaluated

Worth understanding before you write one, because it explains why the file looks
the way it does.

1. **Detect.** The document's format, spec version, and encoding are read from the
   document itself.
2. **Schema.** The document is validated structurally against the version it
   declares, then against the profile's `schema` block (version floors, signature,
   deprecated versions).
3. **Rules.** Each rule in `rules` runs at its `scope`: once for `document`, once
   per component for `component`, or over the graph for `dependency`. A rule names
   a `field` and a list of `validators`.
4. **License policy.** If the profile has a `license_policy`, every declared
   license is evaluated for its `use_case`.
5. **Verdict and score.** Findings are folded into one verdict by severity, and
   into five category scores by `category`, weighted by the profile's `scoring`.

Every layer is driven by the same file, which is why one `--profile` argument
answers all three questions.

## The smallest useful profile

Three fields of identity and one rule:

{: .warning }
**Name the file after the `id`.** A profile is found by filename, not by the
`id` inside it, so `id: acme-minimum` has to live in `acme-minimum.yaml` (or
`.yml`). A mismatch is refused when the profile loads, naming both and either
fix — it used to load and then report the other name in every finding.

```yaml
id: acme-minimum
name: ACME internal SBOM minimum

rules:
  - id: acme-purl
    scope: component
    severity: MUST
    category: Completeness
    citation: "ACME Engineering Standard 7.4"
    field: purl
    validators: [present, purl_wellformed]
```

Save it as `acme-minimum.yaml` in a directory of your own and run it:

```bash
ossbomer validate --profile acme-minimum --file sbom.json --profile-path ./profiles
```

The filename should match the `id`, since that is what the search resolves.

## Extending an existing profile

Usually you do not want to start from nothing. You want an existing standard plus
your own additions:

```yaml
id: acme-shipping-bar
name: ACME shipping bar
extends: [eu-cra-annex-i, fedramp-sbom]

rules:
  - id: acme-namespace-tag
    scope: component
    severity: MUST
    category: Provenance
    citation: "ACME Engineering Standard 7.4"
    field: purl
    validators: [present]
```

`extends` pulls in every rule from those profiles. Your `rules` are added on top.
Because you reference the public profiles by id rather than copying them, catalog
updates reach you without a merge.

## Dropping a rule you disagree with

`excludes` removes inherited rules by id:

```yaml
id: acme-shipping-bar
extends: [eu-cra-annex-i]
excludes: [cra-top-level-dependencies]
```

Rule ids are effectively API, so name yours deliberately if others might extend
your profile.

{: .tip }
Prefer `excludes` over lowering a severity. An excluded rule is visibly absent, and
the next person can see the decision was made. A quietly downgraded MUST looks like
the standard simply does not require it.

## Adjusting the score without changing pass or fail

Weights change what the score emphasizes, and never change the verdict:

```yaml
id: acme-provenance-heavy
extends: [ntia-min-elements]

scoring:
  weights:
    Completeness: 0.10
    Accuracy: 0.20
    Consistency: 0.10
    Provenance: 0.55
    Freshness: 0.05
```

Weights are normalized, so they need not sum to 1.0. Set a category to 0 to keep it
reported but out of the composite.

## Adding license policy

Bind a use case, and optionally override individual identifiers:

```yaml
id: acme-mobile
name: ACME mobile release gate
extends: [eu-cra-annex-i]

license_policy:
  engine: ospac
  use_case: mobile
  rules:
    - spdx_id: LGPL-2.1-only
      allowed: true
      reason: "Reviewed 2026-03; dynamically linked only."
```

Always write the `reason`. It appears in the report, and it is what stops someone
re-litigating the exception in a year.

Drop `engine` if you want only your inline rules, which removes the ospac
dependency entirely. Details on
[License policy]({{ site.baseurl }}/guide/license-policy).

## Writing a regional profile

If you are filling one of the [uncovered
jurisdictions]({{ site.baseurl }}/guide/profiles), the work is transcription rather
than invention:

1. Get the actual published guidance.
2. For each requirement, decide the scope, the field, and the severity **the
   document itself assigns**. Do not promote a recommendation to MUST because it
   seems important.
3. Put the clause in `citation`, precisely enough that a reader can find it.
4. Fill in `sources` with the document name, reference, and URL.

```yaml
id: acme-jp-meti
name: METI SBOM guidance (unofficial)
version: "2.0"
sources:
  - name: METI
    ref: "Guidance on Introduction of Software Bill of Materials (SBOM), v2.0"
    url: https://www.meti.go.jp/
```

{: .warning }
Mark unofficial transcriptions as unofficial in the `name`, as above. A profile
that reads like an authoritative implementation of a standard, but was assembled
from a summary, produces confident and wrong compliance answers.

## Where profiles are found

In order:

1. Directories passed to `--profile-path`
2. Directories in `OSSBOMER_PROFILE_PATH`, separated by the platform path
   separator
3. The bundled catalog

The first match wins, so an overlay sharing an id with a shipped profile replaces
it. `--profile` also accepts a path to a file directly, which skips the search.

```bash
export OSSBOMER_PROFILE_PATH=/opt/acme/profiles
ossbomer validate --profile acme-shipping-bar --file sbom.json
```

## Checking your work

```bash
ossbomer profiles --profile-path ./profiles    # is it found, and is the name right?
ossbomer validators                            # which validators can I call?
```

A profile that fails to load is still listed by id, so if you see the id without a
name, the file has a syntax problem.

Run it against an SBOM you already understand. A new profile that passes everything
on its first run usually means a typo in a `field` name rather than a clean bill of
health.

Full key-by-key detail is in
[Profile format]({{ site.baseurl }}/reference/profile-format).
