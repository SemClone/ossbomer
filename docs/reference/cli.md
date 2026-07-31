---
title: CLI reference
layout: default
parent: Reference
nav_order: 1
---

# CLI reference
{: .no_toc }

Every command and flag.

1. TOC
{:toc}

## ossbomer

```
ossbomer [--version] COMMAND [OPTIONS]
```

| Flag | Description |
| ---- | ----------- |
| `--version` | Print the installed version and exit |
| `--help` | Show help for the group or any command |

## ossbomer validate

Validate an SBOM against one or more profiles.

```
ossbomer validate --profile NAME [--profile NAME ...] --file PATH
                  [--format console|json|sarif] [--profile-path DIR]
```

| Flag | Required | Default | Description |
| ---- | -------- | ------- | ----------- |
| `--profile NAME` | yes | — | Profile to validate against. Repeat for several; each is evaluated independently. |
| `--file PATH` | yes | — | Path to the SBOM. Must exist. |
| `--format` | no | `console` | One of `console`, `json`, `sarif`. |
| `--profile-path DIR` | no | — | Extra directories to search for profiles, separated by the platform path separator (`:` on Linux and macOS, `;` on Windows). |

Format notes:

- **`console`** prints one block per profile with the verdict, the five category
  scores, and the top issues.
- **`json`** emits an object carrying the document path and one entry per profile
  under `results`. Gate on `verdict` when the exit code is not strict enough.
- **`sarif`** emits one run per profile, suitable for GitHub code scanning.

The JSON shape:

```json
{
  "sbom": "sbom.json",
  "results": [
    {
      "profile": "ntia-min-elements",
      "name": "NTIA Minimum Elements for an SBOM",
      "verdict": "FAIL",
      "score": 63,
      "schema_valid": true,
      "categories": {"Completeness": 63, "Accuracy": 41, "Consistency": 75,
                     "Provenance": 68, "Freshness": 70},
      "sources": [
        {"name": "NTIA", "ref": "The Minimum Elements For a Software Bill of Materials (SBOM), 2021-07-12",
         "url": "https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom"}
      ],
      "findings": [
        {"rule_id": "ntia-timestamp", "layer": "conformance", "severity": "MUST",
         "category": "Freshness", "verdict": "FAIL", "path": "document",
         "citation": "NTIA: Timestamp",
         "message": "rfc3339_utc: '2010-01-29T18:30:22' lacks a UTC/timezone designator"}
      ]
    }
  ]
}
```

`findings` carries every rule outcome, not just failures, so the run above has 17
entries where only 4 are MUST violations. `sources` comes from the profile.

`results` is a list even for a single profile, so the same consumer handles one
profile or four. Per-category scores are under `categories`, and the profile id is
`profile`.

## ossbomer profiles

List the catalog, including any overlay directories.

```
ossbomer profiles [--profile-path DIR]
```

Prints the profile id and its full name, one per line. A profile that fails to
load is still listed by id rather than aborting the listing, so a malformed
overlay does not hide the rest of the catalog.

## ossbomer validators

List the field validators profiles can call.

```
ossbomer validators
```

The shipped set:

| Validator | Passes when |
| --------- | ----------- |
| `present` | The field has a value that is not `NOASSERTION`, `NONE` or empty. |
| `declared` | The field has a value **or** an explicit `NOASSERTION`. Silence fails. Use where a standard lets an author say they do not know. |
| `non_placeholder` | The value is not `TODO`, `TBD`, `changeme`, `n/a` and friends. |
| `format_regex` | The value matches `pattern`. |
| `rfc3339_utc` | The timestamp parses as RFC 3339 and carries a timezone. |
| `semver_or_calver` | The version looks like SemVer or CalVer. |
| `purl_wellformed` | The value parses as a Package URL. |
| `spdx_license_expression` | The string parses as an SPDX expression. |
| `license_spdx_normalized` | Every declaration resolves to SPDX. Reads the declarations, so it can say "unresolvable free text" rather than complaining about expression syntax. |
| `license_in_spdx_field` | No valid SPDX expression is hiding in CycloneDX's free-text `license.name` slot. |
| `hash_algorithm_in_set` | A hash uses one of `algs`. |
| `hash_wellformed` | Each digest is hexadecimal and the length its declared algorithm produces. |
| `format_version_at_least` | The spec version meets `min_versions`. |
| `format_version_not_deprecated` | The spec version is not one the format's maintainers retired. |
| `dependency_completeness` | Every component appears in the dependency graph. |
| `known_unknowns_declared` | A gap is explicit rather than silent. |
| `references_vex` | The document references VEX or vulnerability data. |
| `signed_with_x509` | The document carries a signature. |

`declared` and `present` differ in one way that matters: `present` fails an
explicit `NOASSERTION`, `declared` passes it and fails silence instead. Standards
that ask authors to state what they do not know want the second.

Plugins registered through the entry point are included, so `ossbomer validators`
reflects what is actually installed rather than this fixed list.

## Exit codes

| Exit | Condition |
| ---- | --------- |
| `0` | No profile returned FAIL |
| `1` | At least one profile returned FAIL |
| `2` | The document could not be parsed, the invocation was invalid, or a named profile is withdrawn |

See [Verdicts and exit codes]({{ site.baseurl }}/reference/verdicts) for how a set
of findings becomes a verdict.

## Library use

The CLI is a thin wrapper. The same thing from Python:

```python
from ossbomer.core.runner import run

for result in run("sbom.json", ["eu-cra-annex-i", "ntia-min-elements"]):
    print(result.profile_id, result.verdict.value, result.score)
```

`run` takes an optional list of extra profile directories, matching
`--profile-path`.
