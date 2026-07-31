---
title: Schema policy
layout: default
parent: Guide
nav_order: 4
---

# Schema policy
{: .no_toc }

Gating on the document's own spec version, not just its structure.

1. TOC
{:toc}

## Validation follows the document

Structural validation is judged against the version the document declares, using
`cyclonedx-python-lib` and `spdx-tools` rather than schemas copied into this repo.
A CycloneDX 1.4 file is checked as 1.4. Nothing is hardcoded, so format releases
do not require an ossbomer release.

See [SBOM support]({{ site.baseurl }}/reference/sbom-support) for the version and
encoding matrix.

## Requiring a version floor

A profile can also refuse documents that are structurally fine but too old for the
standard it represents:

```yaml
schema:
  min_versions:                    # floor: new enough for this regulation
    spdx: "2.3"
    cyclonedx: "1.5"
  require_signature: true
  deprecated_versions_forbidden: true   # reject versions the format has retired
  deprecated_versions:                  # optional: override the default set
    cyclonedx: ["1.2"]
```

## Two different questions

`min_versions` and `deprecated_versions_forbidden` look similar and are not:

- **`min_versions`** asks "is this new enough for this standard?" The floor comes
  from the regulation. CRA wants fields that only exist from a certain version on.
- **`deprecated_versions_forbidden`** asks "is this a version the format's own
  maintainers have moved on from?" The answer comes from the format, and has
  nothing to do with any regulation.

A profile with a high floor only needs the first. One that deliberately accepts a
broad range wants both, so it can take 1.3 through 1.6 while still rejecting 1.2.

`require_signature` checks that a signature is present. Verifying the signing
envelope itself (COSE, JWS, x509) is on the roadmap and is not done today, so
treat this as a presence check rather than proof of authenticity.
