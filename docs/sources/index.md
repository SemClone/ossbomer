---
title: Source documents
layout: default
nav_order: 5
---

# Source documents
{: .no_toc }

Every profile in the catalog is a transcription of a published document. This
page is the evidence: what was read, which version, and the checksum of the exact
bytes, so a finding can be traced to a clause rather than taken on faith.

1. TOC
{:toc}

## Why this exists

A profile that cites a clause nobody checked is worse than no profile. It reports
a confident verdict against requirements that may not say what the rule claims.

That is not hypothetical. The `eu-cra-annex-vii` profile shipped in 2.0.0 with
rules citing "CRA Annex VII §8(a)", "§8(b)" and "§8(c)". Those sub-points do not
exist. Annex VII point 8 is a single sentence naming no data field. The profile
was withdrawn in 2.1.0 and replaced by `eu-cra-annex-i`, which encodes the clause
that does constrain SBOM content. The extract in this folder is how you can check
that for yourself in about thirty seconds.

## Verifying a document

Each entry below gives a SHA-256. For the documents held in this repository:

```bash
shasum -a 256 docs/sources/documents/cisa-2026-sbom-minimum-elements.pdf
```

For the ones held by reference only, download from the publisher's URL and
compare. A mismatch means the publisher revised the document in place, which is
itself worth knowing: it means a profile citing it may now be stale.

## Held in this repository

Redistributed because the publisher's terms allow it.

| Document | Version / date | Profile | Terms |
| -------- | -------------- | ------- | ----- |
| [CISA, 2026 Minimum Elements for a Software Bill of Materials](documents/cisa-2026-sbom-minimum-elements.pdf) | 2026-07-29 | `cisa-2026-min` | TLP:CLEAR, "may be distributed without restriction"; US Government work |
| [NTIA, The Minimum Elements For a Software Bill of Materials](documents/ntia-2021-sbom-minimum-elements.pdf) | 2021-07-12 | `ntia-min-elements` | US Government work, 17 U.S.C. §105 |
| [OpenChain Telco SBOM Guide](documents/openchain-telco-sbom-guide-v1.1.md) | v1.1, approved 2025-03-20 | `openchain-telco-v1.1` | CC0-1.0 per the Telco WG repository |
| [Regulation (EU) 2024/2847, extracts](documents/eu-cra-2024-2847-extracts.txt) | OJ L, 2024-11-20 | `eu-cra-annex-i` | Commission Decision 2011/833/EU |
| [Executive Order 14028, Improving the Nation's Cybersecurity](documents/eo-14028-improving-the-nations-cybersecurity.pdf) | 86 FR 26633, 2021-05-12 | `fedramp-sbom` | US Government work, 17 U.S.C. §105 |

Checksums:

```
b42046c466ea3afcd2110b9b20607896d7172d6aaf66051459a769d0aa7456fc  cisa-2026-sbom-minimum-elements.pdf
b0fbbe5e3c5773977df1f402eceb845c4d5715a02cde4d967e54aef51856b716  ntia-2021-sbom-minimum-elements.pdf
927e0ecccf4f40ce4172a4e2a252e440a62d02b2626513d89c57f4e7a4db5760  openchain-telco-sbom-guide-v1.1.md
aa9b059df1a42d870520c5eb428f3a932b0f1b93464e1b4ab5ba24701c3efabc  eu-cra-2024-2847-extracts.txt
250578b7bdd468cb67e4f64d332f6648694302257670ae966d37b21aa138a282  eo-14028-improving-the-nations-cybersecurity.pdf
```

The EU entry is an extract rather than the full Official Journal: Annex I Part II
verbatim and Annex VII complete, which are the only two clauses bearing on SBOM
content. The retrieval URL is in the file header.

## Held by reference

Not redistributed. Both publishers reserve copyright without granting reuse, so
this repository records the URL, the version and the checksum instead of the
bytes. Download from the publisher and verify against the hash below.

| Document | Version / date | Profile | Why not vendored |
| -------- | -------------- | ------- | ---------------- |
| [BSI TR-03183-2, Cyber Resilience Requirements for Manufacturers and Products, Part 2: SBOM](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile) | v2.1.0 | `bsi-tr-03183-v2.1` | "© Federal Office for Information Security 2023 - 2025", no reuse grant |
| [BSI TR-03183-2](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_2_0.pdf?__blob=publicationFile) | v2.2.0 | not yet profiled | same |
| [CERT-In, Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM](https://www.cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf) | v2.0, 2025-07-09 | `cert-in-v2.0` | Government of India, no reuse grant located |

```
dda0ccd9b6148571d1d12241a1618b30027f22bc15e24248fdd21a011e62845c  BSI-TR-03183-2_v2_1_0.pdf
62818650412344c17bfbac5e1866d86416ccef61988c8c906ae7c535432f93cc  BSI-TR-03183-2_v2_2_0.pdf
28aa48f329114d665f8e4f8c4d2f33baf4981e29168a318e6e719c11a5ff5151  TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf
```

{: .note }
BSI TR-03183-2 v2.2.0 is published and the `bsi-tr-03183-v2.1` profile targets
v2.1.0. The profile is not stale by accident: it names the version it encodes.
A v2.2 profile is open work.

## Composed rather than transcribed

| Profile | Status |
| ------- | ------ |
| `fedramp-sbom` | Resolved in 2.1.0. FedRAMP publishes no SBOM data field list; EO 14028 §4(e)(vii) requires an SBOM and §4(f) delegates the field list to Commerce/NTIA, whose document CISA now maintains. The profile composes `cisa-2026-min` rather than restating fields under a FedRAMP label. The EO is held above. |
| `aibom-v0.1` | Deliberately net-new. No regulator has published AIBOM minimum elements, which the profile's own `sources` states. Its rules are advisory (`SHOULD`) for that reason. |

## Where the license profiles come from

`license-distribution`, `license-mobile`, `license-saas` and `license-internal`
carry no external standard. They select a use case in
[ospac](https://pypi.org/project/ospac/), which holds the policy. The obligations
they encode are ospac's, not a regulator's.
