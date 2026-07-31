---
title: Profiles
layout: default
parent: Guide
nav_order: 1
---

# Profiles
{: .no_toc }

A profile is one file that says what "good" means for one regulation, program, or
use case.

1. TOC
{:toc}

## The catalog

Twelve profiles ship with the tool. Run `ossbomer profiles` to see them locally.

### Regulations and programs

| Profile | Standard |
| ------- | -------- |
| `ntia-min-elements` | NTIA Minimum Elements for an SBOM (2021) |
| `cisa-2025-min` | CISA 2025 Draft SBOM Minimum Elements |
| `eu-cra-annex-vii` | EU Cyber Resilience Act, Annex VII §8 |
| `bsi-tr-03183-v2.1` | BSI TR-03183 Part 2 v2.1 |
| `cert-in-v2.0` | India CERT-In SBOM Guidelines v2.0 |
| `openchain-telco-v1.1` | OpenChain Telco SBOM Quality v1.1 |
| `fedramp-sbom` | FedRAMP SBOM requirements |
| `aibom-v0.1` | AI Bill of Materials (net-new, advisory) |

### License use cases

| Profile | Use case |
| ------- | -------- |
| `license-distribution` | Distributed commercial product |
| `license-mobile` | Mobile application |
| `license-saas` | Network service |
| `license-internal` | Internal use only |

`aibom-v0.1` is advisory. It is our own construction rather than a published
standard, and its rules sit at SHOULD until the IR carries model, weights, and
training-data entities.

## Regional coverage, and what is missing

By jurisdiction, what ships today:

| Region | Covered by | Status |
| ------ | ---------- | ------ |
| United States | `ntia-min-elements`, `cisa-2025-min`, `fedramp-sbom` | Yes |
| European Union | `eu-cra-annex-vii` | Yes |
| Germany | `bsi-tr-03183-v2.1` | Yes |
| India | `cert-in-v2.0` | Yes |
| Telecom sector | `openchain-telco-v1.1` | Yes, sector rather than region |
| Japan | none | **Not covered** |
| United Kingdom | none | Not covered |
| South Korea, China, Australia | none | Not covered |

{: .note }
Japan's METI SBOM guidance is a real and known gap. It is not shipped because
writing a profile means transcribing the actual clauses and citing them, and a
profile with invented rules is worse than no profile: it would report a confident
verdict against requirements nobody published. The same holds for the other
uncovered jurisdictions.

If you need one of these now, write it as an overlay. See
[Writing your own profile]({{ site.baseurl }}/guide/custom-profiles). Contributions
of a properly cited regional profile are very welcome.

## Picking one

Match the profile to the obligation you actually have. If you sell into the EU,
`eu-cra-annex-vii`. If you are answering a US federal procurement question,
`ntia-min-elements` or `fedramp-sbom`. If a customer sent you a questionnaire
citing BSI, `bsi-tr-03183-v2.1`.

Run several at once when you have several obligations. Each answers separately:

```bash
ossbomer validate \
  --profile eu-cra-annex-vii \
  --profile ntia-min-elements \
  --file sbom.json
```

License profiles are orthogonal to the regulation ones, so pairing a regulation
profile with the license profile matching how you ship is a common combination:

```bash
ossbomer validate --profile eu-cra-annex-vii --profile license-mobile --file sbom.json
```

## Rule severity

Every rule in a profile carries a severity, which is what turns a list of
findings into a verdict:

| Severity | Meaning |
| -------- | ------- |
| `MUST` | Required. Failing it fails the profile. |
| `MUST_WHERE_AVAILABLE` | Required when the document carries the field at all. Absent field warns; present but wrong fails. |
| `SHOULD` | Recommended. Failing it warns. |
| `MAY` | Informational. Reported, never changes the verdict. |

Rules also carry a citation naming the clause they come from, so a finding can be
traced back to the source text rather than taken on faith.

## Composing and overriding

Profiles compose with `extends` and subtract with `excludes`. That is how you keep
an internal standard without copying the public catalog into your repo:

```yaml
id: acme-shipping-bar
extends: [eu-cra-annex-vii, fedramp-sbom]
excludes: [cra-component-hash]
rules:
  - id: acme-namespace-tag
    scope: component
    severity: MUST
    category: Provenance
    citation: "Internal ACME Engineering Standard 7.4"
    field: purl
    validators: [present]
```

Put that file in a directory of your own and point at it:

```bash
ossbomer validate \
  --profile acme-shipping-bar \
  --file sbom.json \
  --profile-path ./private-profiles
```

Your overlay refers to public rule IDs by name, so catalog updates reach you
without a merge. `--profile-path` takes several directories separated by the
platform path separator (`:` on Linux and macOS).

For the full set of keys a profile file accepts, see
[Profile format]({{ site.baseurl }}/reference/profile-format).
