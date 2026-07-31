# ossbomer

Profile-driven SBOM validation, conformance, and license policy for SPDX and CycloneDX.

Most SBOM tools answer one question. ossbomer answers three in a single pass:

- Is the document structurally valid, judged against the spec version it declares?
- Does it carry the fields a given regulation asks for, at that regulation's severity?
- Given how you ship this software, does policy allow the licenses it declares?

You pick a profile, which is one YAML file binding all three. So "does this SBOM
meet the EU CRA" is one argument instead of three tool runs and a spreadsheet.

Thirteen usable profiles ship with it, covering CISA 2026, NTIA 2021, EU CRA,
BSI TR-03183, India CERT-In, OpenChain Telco, FedRAMP, AIBOM, and four license
use cases. Every rule cites the clause it comes from, and the documents those
citations point at are in the repository with checksums, so a finding can be
traced rather than taken on trust.

Full documentation: **https://semclone.github.io/ossbomer/**

## Install

Requires Python 3.9 or newer; tested through 3.13.

```bash
pip install "ossbomer[oslc]"
```

The `oslc` extra pulls in [ospac](https://pypi.org/project/ospac/), which evaluates
license policy. Every `license-*` profile needs it. Plain `pip install ossbomer`
works if you only need schema and conformance.

Upgrading from 0.1.4 is a breaking change: that release predates the profile
engine, and the per-layer commands it shipped now behave differently. See the
[changelog](https://github.com/SemClone/ossbomer/blob/main/CHANGELOG.md).

## Use

```bash
ossbomer validate --profile cisa-2026-min --file sbom.json
```

```
============================================================
Profile: CISA 2026 SBOM Minimum Elements
Verdict: FAIL (191 MUST violations)
Quality score: 64 / 100
  Completeness: 74
  Accuracy:     60
  Consistency:  100
  Provenance:   42
  Freshness:    60
Top issues:
  1. Freshness: schema-min-version: cyclonedx 1.4 is below required minimum 1.5 [document.specVersion]
  2. Provenance: cisa26-sbom-author-signature: signed_with_x509: SBOM is not signed [document]
  3. Freshness: cisa26-sbom-data-format-version: format_version_at_least: cyclonedx 1.4 is below required minimum 1.5 [document]
============================================================
```

Most real SBOMs fail a minimum-elements profile today. The verdict answers
whether the document meets the standard; the score tells you how far off it is.

`--profile` repeats, and each profile is evaluated on its own with its own verdict
and score. Nothing is averaged between them, because a good NTIA score tells you
nothing about CRA readiness.

Output can be `console`, `json`, or `sarif`. The exit code works as a CI gate: 0 if
nothing failed, 1 if a profile failed, 2 if the file could not be read or the
profile named is withdrawn. Nothing calls the network.

Declared licenses are normalized to SPDX first, so policy is never asked about a
string it cannot identify. `GPL-2.0+`, `MIT or Apache-2.0`, npm's
`MIT || Apache-2.0` and `Apache 2` all resolve. Family names like `BSD` and
`GPL` do not, because they name no single license, and they are reported as
unresolved rather than guessed at.

## Formats

| Format | Versions | JSON | XML | Tag-value | YAML |
| ------ | -------- | ---- | --- | --------- | ---- |
| CycloneDX | 1.3 - 1.6 | yes | yes | not applicable | no such serialization |
| SPDX | 2.2, 2.3 | yes | yes | yes | yes |
| SPDX | 3.0 | structural only | no official schema | not applicable | no |

Validation follows the version the document declares, using `cyclonedx-python-lib`
and `spdx-tools` rather than vendored schemas.

## Documentation

| | |
| --- | --- |
| [Getting started](https://semclone.github.io/ossbomer/getting-started) | Install it and read a result |
| [Profiles](https://semclone.github.io/ossbomer/guide/profiles) | The catalog, and writing your own |
| [License policy](https://semclone.github.io/ossbomer/guide/license-policy) | Use cases, SPDX expressions, overrides |
| [Using it in CI](https://semclone.github.io/ossbomer/guide/ci) | Gating a build, SARIF and code scanning |
| [Verdicts and exit codes](https://semclone.github.io/ossbomer/reference/verdicts) | How findings become one answer |
| [CLI reference](https://semclone.github.io/ossbomer/reference/cli) | Every command and flag |

## Contributing

See [CONTRIBUTING.md](https://github.com/SemClone/ossbomer/blob/main/CONTRIBUTING.md).
Adding a profile is the most approachable place to start, since profiles are YAML
rather than code.

Every change lands through a pull request with green CI. Contributors sign a CLA
once, in the pull request, by replying to the bot. Participation is governed by the
[Code of Conduct](https://github.com/SemClone/ossbomer/blob/main/CODE_OF_CONDUCT.md).

Please do not open a public issue for a security vulnerability. Report it as
described in [SECURITY.md](https://github.com/SemClone/ossbomer/blob/main/SECURITY.md).

## License

Apache License 2.0. See
[LICENSE](https://github.com/SemClone/ossbomer/blob/main/LICENSE).
