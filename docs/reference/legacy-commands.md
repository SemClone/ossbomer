---
title: Legacy commands
layout: default
parent: Reference
nav_order: 5
---

# Legacy commands
{: .no_toc }

The pre-2.0 per-layer commands still work. They are a convenience, not a
compatibility guarantee.

1. TOC
{:toc}

## Status

Before 2.0 the three layers were separate tools. Those entry points still exist:

```bash
ossbomer-schema sbom.json                      # structural validation only
ossbomer-conformance --file sbom.json          # ntia-min-elements + eu-cra-annex-vii
ossbomer-oslc --file sbom.json --use-case saas # the matching license-* profile
```

{: .note }
These are kept because they are cheap to keep, not because anything depends on
them. New work should use `ossbomer validate`. Treat these as convenience shims
that may eventually go away rather than a supported interface to build on.

## What they actually are

Thin front-ends over the same engine as `ossbomer validate`. They preselect
profiles and nothing else, so all of these give the same answer for the same
document:

```bash
ossbomer-conformance --file sbom.json
ossbomer validate --profile ntia-min-elements --profile eu-cra-annex-vii --file sbom.json
```

There is no separate code path, so there is no behavior to drift apart. They also
accept `--profile` and `--profile-path`, which means anything the engine can do,
they can do.

## Exit codes

All four commands share one convention:

| Exit | Meaning |
| ---- | ------- |
| `0` | No profile returned FAIL (schema command: document is valid) |
| `1` | A profile returned FAIL (schema command: document is invalid) |
| `2` | The document could not be processed, or the invocation was invalid |

## Removed flags

`--rules` and `--license-rules` are gone. They pointed at file formats that no
longer exist, replaced by profiles.

They now report an error naming the replacement rather than being accepted and
ignored. Silently accepting a rules file and then not applying it would mean a
build that reports PASS while checking nothing.

## Moving off them

Straightforward, since they are only profile presets:

| Old | New |
| --- | --- |
| `ossbomer-schema sbom.json` | `ossbomer validate --profile <any> --file sbom.json` (schema runs as part of every profile) |
| `ossbomer-conformance --file sbom.json` | `ossbomer validate --profile ntia-min-elements --profile eu-cra-annex-vii --file sbom.json` |
| `ossbomer-oslc --file sbom.json --use-case saas` | `ossbomer validate --profile license-saas --file sbom.json` |

Naming the profiles explicitly is worth the extra characters: the old commands
hid which standards they were checking, so a passing build did not tell you what
it had actually verified.
