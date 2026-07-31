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

```
dependency_completeness   known_unknowns_declared   references_vex
format_regex              non_placeholder           rfc3339_utc
format_version_at_least   present                   semver_or_calver
format_version_not_deprecated  purl_wellformed      signed_with_x509
hash_algorithm_in_set     spdx_license_expression
```

Plugins registered through the entry point are included, so this reflects what is
actually installed rather than a fixed list.

## Exit codes

| Exit | Condition |
| ---- | --------- |
| `0` | No profile returned FAIL |
| `1` | At least one profile returned FAIL |
| `2` | The document could not be parsed, or the invocation was invalid |

See [Verdicts and exit codes]({{ site.baseurl }}/reference/verdicts) for how a set
of findings becomes a verdict.

## Library use

The CLI is a thin wrapper. The same thing from Python:

```python
from ossbomer.core.runner import run

for result in run("sbom.json", ["eu-cra-annex-vii", "ntia-min-elements"]):
    print(result.profile_id, result.verdict.value, result.score)
```

`run` takes an optional list of extra profile directories, matching
`--profile-path`.
