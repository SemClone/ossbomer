---
title: Profile format
layout: default
parent: Reference
nav_order: 3
---

# Profile format
{: .no_toc }

Every key a profile file accepts.

1. TOC
{:toc}

## A complete example

This is `ntia-min-elements` trimmed to two rules, showing every top-level section:

```yaml
id: ntia-min-elements
name: NTIA Minimum Elements for an SBOM
version: "2021-07"
sources:
  - name: NTIA
    ref: "The Minimum Elements For a Software Bill of Materials (SBOM), 2021-07-12"
    url: https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom

schema:
  min_versions:
    spdx: "2.2"
    cyclonedx: "1.3"

rules:
  - id: ntia-timestamp
    scope: document
    severity: MUST
    category: Freshness
    citation: "NTIA: Timestamp"
    field: timestamp
    validators: [present, rfc3339_utc]

  - id: ntia-supplier
    scope: component
    severity: MUST_WHERE_AVAILABLE
    category: Completeness
    citation: "NTIA: Supplier Name"
    field: supplier
    validators: [present]

scoring:
  weights:
    Completeness: 0.40
    Accuracy: 0.15
    Consistency: 0.15
    Provenance: 0.20
    Freshness: 0.10
  thresholds:
    version_coverage_min: 0.90
```

## Identity

| Key | Required | Description |
| --- | -------- | ----------- |
| `id` | yes | Stable identifier, and what `--profile` takes. Match the filename. |
| `name` | yes | Human-readable name, shown in reports and `ossbomer profiles`. |
| `version` | no | Version of the standard this tracks, not of ossbomer. |
| `sources` | no | Where the requirements come from: `name`, `ref`, `url`. Worth filling in, since it is how a reader checks your work. |

## Composition

| Key | Description |
| --- | ----------- |
| `extends` | List of profile ids to inherit rules from. |
| `excludes` | List of rule ids to drop from what was inherited. |

```yaml
extends: [eu-cra-annex-i, fedramp-sbom]
excludes: [cra-top-level-dependencies]
```

Your own `rules` are added on top. Referring to inherited rules by id means
catalog updates reach you without a merge.

## schema

Covered in full on [Schema policy]({{ site.baseurl }}/guide/schema-policy).

| Key | Description |
| --- | ----------- |
| `min_versions` | Per-format version floor, e.g. `spdx: "2.3"`. |
| `require_signature` | Require a signature to be present. |
| `deprecated_versions_forbidden` | Reject versions the format has retired. |
| `deprecated_versions` | Override the default deprecated set per format. |

## rules

| Key | Required | Description |
| --- | -------- | ----------- |
| `id` | yes | Unique within the profile. This is what `excludes` targets, so treat it as API. |
| `scope` | yes | `document`, `component`, or `dependency`. |
| `severity` | yes | `MUST`, `MUST_WHERE_AVAILABLE`, `SHOULD`, or `MAY`. |
| `category` | yes | One of the five scoring categories. |
| `citation` | yes | The clause this comes from, quoted in the finding. |
| `field` | usually | The IR field to check. Omitted when the validator works on the whole scope. |
| `validators` | yes | Validators to run, in order. |

`scope` decides what the rule runs against: once for `document`, once per
component for `component`, and over the dependency graph for `dependency`.

Available validators are listed by `ossbomer validators` and in the
[CLI reference]({{ site.baseurl }}/reference/cli).

## license_policy

Covered in full on [License policy]({{ site.baseurl }}/guide/license-policy).

| Key | Description |
| --- | ----------- |
| `engine` | `ospac`, or omit to use only inline `rules`. |
| `use_case` | Passed to ospac as `distribution_type`. |
| `policy_path` | Your own ospac policy directory, relative to the profile file. |
| `context` | Extra keys your policy matches on, e.g. `linking_type`. |
| `rules` | Per-identifier overrides: `spdx_id`, `allowed`, `reason`. |

`spdx_id` is required in an override, and must be a single SPDX identifier.
Overrides are matched by exact identifier, so a rule without one would match
nothing; that is an error at load time rather than a silently inert rule. An
`expression` key is rejected for the same reason — use the engine for
expression-level decisions.

## scoring

| Key | Description |
| --- | ----------- |
| `weights` | Relative weight per category in the composite. |
| `thresholds` | Signal thresholds, e.g. `version_coverage_min`. |

Weights are normalized, so they do not have to sum to 1.0. Set a category to 0 to
keep it out of the composite while still reporting it.

`scoring` is inherited through `extends` like everything else, so a profile that
extends a parent and omits `scoring` scores with the parent's weights rather than
falling back to the built-in defaults.

## Using your own profile

Put the file in a directory and point at it:

```bash
ossbomer validate --profile acme-shipping-bar --file sbom.json --profile-path ./private-profiles
```

`--profile-path` accepts several directories separated by the platform path
separator. Overlays are searched before the bundled catalog, so a file sharing an
id with a shipped profile replaces it.

You can also set the search path in the environment, which is often tidier for CI:

```bash
export OSSBOMER_PROFILE_PATH=/opt/acme/profiles:/opt/acme/overlays
ossbomer validate --profile acme-shipping-bar --file sbom.json
```

The order is `--profile-path`, then `OSSBOMER_PROFILE_PATH`, then the bundled
catalog. `--profile` also accepts a path to a file directly, which skips the search
entirely.
