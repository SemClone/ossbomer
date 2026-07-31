---
title: Home
layout: default
nav_order: 1
---

# ossbomer
{: .fs-9 }

Checks an SBOM three ways in one pass: is the file valid, does it satisfy a
regulation, and do its licenses fit your use case.
{: .fs-6 .fw-300 }

[Get started]({{ site.baseurl }}/getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Profiles]({{ site.baseurl }}/guide/profiles){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[CLI reference]({{ site.baseurl }}/reference/cli){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[GitHub](https://github.com/SemClone/ossbomer){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What it does

Most SBOM tools answer one question. ossbomer answers three at once, for both
SPDX and CycloneDX:

- **Schema.** Is the document structurally valid, judged against the spec version
  it actually declares?
- **Conformance.** Does it carry the fields a given regulation or program asks
  for, at the severity that regulation assigns them?
- **License policy.** Given how you ship this software, does policy allow the
  licenses the SBOM declares?

You pick a *profile*. A profile is one YAML file that binds all three, so
"does this SBOM meet the EU CRA" is a single argument rather than three tool runs
and a spreadsheet.

```bash
ossbomer validate --profile eu-cra-annex-vii --file sbom.json
```

Each profile returns its own verdict and its own quality score. Ask for four
profiles and you get four independent answers. Scores are never averaged
together, because a good NTIA score tells you nothing about CRA readiness.

## What comes with it

Twelve profiles ship in the box, covering NTIA, CISA 2025, EU CRA, BSI TR-03183,
India CERT-In, OpenChain Telco, FedRAMP, AIBOM, and four license use cases. See
[Profiles]({{ site.baseurl }}/guide/profiles) for the full catalog.

Output is console text, JSON, or SARIF, and the exit code is meant to be used
directly as a CI gate. Nothing calls the network unless you opt in.

## Where to go next

| If you want to | Read |
| -------------- | ---- |
| Install it and run it once | [Getting started]({{ site.baseurl }}/getting-started) |
| Know which profile to pick | [Profiles]({{ site.baseurl }}/guide/profiles) |
| Write or extend a profile | [Writing your own profile]({{ site.baseurl }}/guide/custom-profiles) |
| Understand PASS, WARN, FAIL | [Verdicts and exit codes]({{ site.baseurl }}/reference/verdicts) |
| Gate a build on it | [Using it in CI]({{ site.baseurl }}/guide/ci) |
| Change a license answer | [License policy]({{ site.baseurl }}/guide/license-policy) |
| Write your own profile | [Profile format]({{ site.baseurl }}/reference/profile-format) |
| Know which formats work | [SBOM support]({{ site.baseurl }}/reference/sbom-support) |
