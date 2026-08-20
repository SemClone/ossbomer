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
| `scope` | yes | `document`, `component`, `file`, or `dependency`. An unknown value is refused at load time. |
| `severity` | yes | `MUST`, `MUST_WHERE_AVAILABLE`, `SHOULD`, or `MAY`. |
| `category` | yes | One of the five scoring categories. |
| `citation` | yes | The clause this comes from, quoted in the finding. |
| `field` | usually | The IR field to check. Omitted when the validator works on the whole scope. |
| `fields` | no | Alternative IR fields for a requirement satisfiable more than one way. Takes precedence over `field`. |
| `validators` | yes | Validators to run, in order. |

`scope` decides what the rule runs against: once for `document`, once per
component for `component`, once per file entry for `file`, and over the
dependency graph for `dependency`.

Available validators are listed by `ossbomer validators` and in the
[CLI reference]({{ site.baseurl }}/reference/cli).

### What `field` can name

`field` names an attribute on the normalized document, not a path in the source
file, so one rule works across SPDX and CycloneDX. Both formats are mapped onto
the same shape.

Document scope:

| Field | Holds |
| ----- | ----- |
| `creators` | Everyone credited with creating the SBOM: people, organizations and tools. |
| `tools` | The tool-only subset of `creators`. |
| `tool_versions` | Versions of those tools, kept separate so a rule can ask whether one was declared at all. |
| `timestamp` | When the SBOM data was last changed. |
| `sbom_version` | The revision of the SBOM document. Not the spec version, and not the version of what it describes. |
| `lifecycles` | The lifecycle phase it was generated in, such as `build`. CycloneDX 1.5+ only. |
| `name`, `namespace`, `supplier`, `data_license` | Document metadata. |

Component scope:

| Field | Holds |
| ----- | ----- |
| `name`, `version`, `type` | Component identity. |
| `purl`, `cpe`, `bom_ref` | Identifiers. |
| `supplier`, `author`, `publisher` | Who produced it. |
| `licenses` | Effective license strings: the normalized SPDX form where one resolved, otherwise the raw text. |
| `license_declarations` | The full record per declaration: raw text, which slot it came from, what it normalized to and how. What `license_spdx_normalized` reads. |
| `hashes` | Algorithm to digest. |
| `external_refs`, `properties` | Passed through from the source. |

File scope:

| Field | Holds |
| ----- | ----- |
| `name` | The file's path. SPDX writes it as `fileName`, CycloneDX as the component `name`. |
| `spdx_id` | The element identifier. SPDX's `SPDXID`, CycloneDX's `bom-ref`. |
| `hashes` | Algorithm to digest, the same shape as a component's, so one validator serves both. |
| `licenses`, `copyright` | Per-file declarations, where the document makes them. |

Anything not listed falls back to a dotted lookup into the component's raw source
mapping, so `field: raw.someVendorExtension` works for data the IR does not model.

### File scope, and the two kinds of absence

The file inventory is optional in both formats, and a dependency-level SBOM
legitimately has none. So a `file` rule answers two different questions and only
one of them can be a violation:

| Situation | Verdict |
| --------- | ------- |
| No file inventory at all | `WARN`, whatever the rule's severity |
| A file entry present, required field missing | the rule's severity decides |
| A file entry present, field valid | `PASS` |

The first row does not follow the severity on purpose. A `MUST` file rule would
otherwise fail every SBOM that simply does not enumerate files, which inverts the
requirement. It reports `WARN` rather than nothing so that "not checked" stays
distinguishable from "checked and satisfied".

Within an entry the severity governs as usual, so a `MUST` rule still fails a
file whose checksum is missing — which is what SPDX 2.3 §8.4 asks for, since it
makes `FileChecksum` mandatory on an entry that exists.

{: .note }
A file with no checksum reaches a rule only from CycloneDX. spdx-tools refuses
to parse an SPDX file entry that has none, enforcing §8.4 before any profile
runs.

CycloneDX has no files section: a file is a component whose `type` is `file`.
Those appear in the file inventory *and* stay in the component list, so existing
component rules see exactly what they saw before.

### When a clause accepts more than one field

Some requirements are satisfiable in more than one way. BSI TR-03183-2 §5.2.4
asks for "other unique identifiers (CPE or purl)": either one meets it. Use
`fields` for these, listed in precedence order:

```yaml
- id: bsi-component-identifier
  scope: component
  severity: MUST_WHERE_AVAILABLE
  category: Completeness
  citation: "BSI TR-03183-2 §5.2.4: Other unique identifiers (CPE or purl), if it exists"
  fields: [purl, cpe]
  validators: [present, component_identifier]
```

The first field carrying a real value is what the validators see; `NOASSERTION`
and friends do not count, so a null purl does not shadow a usable CPE. When none
of them holds a value the rule reports absence, which for
`MUST_WHERE_AVAILABLE` is a WARN rather than a violation.

Pick validators that suit every field listed. `purl_wellformed` alongside
`fields: [purl, cpe]` would reject a CPE for not being a purl, which is why
`component_identifier` decides the form per value from its prefix.

{: .note }
Not every field exists in every format. SPDX 2.x has no document-version or
lifecycle-phase field, so `sbom_version` and `lifecycles` are empty there and a
rule requiring them fails for SPDX 2.x documents. That is a true statement about
the format rather than a defect in the document, and `cisa-2026-min` reports it
as such.

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
`expression` key is rejected for the same reason, so use the engine for
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

## Environment variables

| Variable | Effect |
| -------- | ------ |
| `OSSBOMER_PROFILE_PATH` | Extra profile directories, `os.pathsep`-separated. Searched before the bundled catalog. |
| `OSSBOMER_LICENSE_ALIASES` | Extra license normalization tables, `os.pathsep`-separated. See [License policy]({{ site.baseurl }}/guide/license-policy). |
