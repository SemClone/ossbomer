---
title: SBOM support
layout: default
parent: Reference
nav_order: 4
---

# SBOM support
{: .no_toc }

Which formats, versions, and encodings work.

1. TOC
{:toc}

## Matrix

| Format | Version | JSON | XML | Tag-value | YAML |
| ------ | ------- | ---- | --- | --------- | ---- |
| CycloneDX | 1.3 - 1.6 | yes | yes | not applicable | no such serialization |
| SPDX | 2.2, 2.3 | yes | yes | yes | yes |
| SPDX | 3.0 | structural only | no official schema | not applicable | no |

CycloneDX defines no YAML serialization, so there is nothing to support there.
SPDX XML includes RDF/XML, which parses through the same path.

## How versions are handled

A document is validated against the version it declares, not against a version
chosen by the tool. Parsing goes through `cyclonedx-python-lib` and `spdx-tools`
rather than schemas vendored into this repo, so format releases do not require an
ossbomer release.

A profile can still refuse a document that is structurally valid but too old for
the standard it represents. See
[Schema policy]({{ site.baseurl }}/guide/schema-policy).

## SPDX 3.0

{: .note }
SPDX 3.0 is checked structurally, as JSON-LD shape, rather than against a full
schema. The 3.0 tooling ecosystem is still maturing. Conformance rules and scoring
work on 3.0 documents, but do not read a 3.0 PASS as strong a statement as a 2.3
PASS.

There is no official XML serialization for SPDX 3.0, so there is nothing to
support there.

## Encodings

CycloneDX XML is converted to the CycloneDX JSON shape through
`cyclonedx-python-lib` and then follows the same path as JSON, rather than being
parsed by hand.

Every SPDX serialization goes through `spdx-tools`, which dispatches on the file
extension. So JSON, tag-value, XML, RDF/XML, and YAML all work, and coverage for
each is whatever `spdx-tools` provides.

Detection reports the encoding as `json`, `xml`, `tagvalue`, or `yaml`. Note that
`yaml` is SPDX-only, since CycloneDX has no YAML serialization to detect.

## Internal representation

Both formats are normalized into one internal representation before any rule runs.
That is why a profile can be written once and applied to either format, and why a
CycloneDX and an SPDX description of the same software should produce comparable
answers.

The IR does not yet carry AI model, weights, or training-data entities, which is
the reason `aibom-v0.1` rules sit at SHOULD rather than MUST.
