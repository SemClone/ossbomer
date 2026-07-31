# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.1.0] - 2026-07-30

This release changes rule ids and verdicts, not only the profile catalog.
Overlays that exclude a rule by id, and CI gates that act on a verdict, will see
different results than they did on 2.0.0. The specifics are immediately below.

### Breaking
- **Rule ids removed.** `eu-cra-annex-vii` loses all eight (`cra-sbom-author`,
  `cra-timestamp`, `cra-component-name`, `cra-component-version`,
  `cra-component-identifier`, `cra-component-license`, `cra-component-hash`,
  `cra-dependency-completeness`); `fedramp-sbom` loses all eight `fedramp-*`
  ids; `bsi-tr-03183-v2.1` loses `bsi-tool`. An overlay with
  `excludes: [fedramp-component-hash]`, or a consumer keying SARIF or JSON
  output on those ids, breaks.
- **`eu-cra-annex-vii` no longer produces a verdict.** It exits 2 with the reason
  and a pointer to `eu-cra-annex-i`. Emptying its rules was not enough: zero
  findings computes to PASS, so the withdrawn profile briefly reported success
  for a standard nothing was checked against, which in a CI gate turns red to
  green on upgrade.
- **Verdicts change on unchanged documents.** `ntia-min-elements` moves Supplier
  Name to MUST, so documents that warned now fail. `bsi-tr-03183-v2.1` drops its
  signature gate and the `bsi-tool` rule, so documents that failed may now pass.
  `openchain-telco-v1.1` drops PURL to SHOULD. `fedramp-sbom` inherits the full
  CISA 2026 set and is substantially stricter.

### Added
- **`cisa-2026-min` profile.** CISA published the 2026 Minimum Elements for a
  Software Bill of Materials on 2026-07-29, co-sealed by seventeen international
  cybersecurity bodies. It "updates and replaces" the 2021 NTIA minimum elements
  that shipped as `ntia-min-elements`. The profile covers all seventeen data
  fields in its Appendix A: ten are new (SBOM Author Signature, SBOM Data Format
  Name, SBOM Data Format Version, SBOM Generation Context, SBOM Tool Name, SBOM
  Tool Version, SBOM Version, Component Hash Value, Component Hash Algorithm,
  Component License) and four are renamed from 2021 (Supplier Name to Component
  Producer, Other Identifiers to Component Identifiers, Author of SBOM Data to
  SBOM Author, Version of the Component to Component Version).
- `Document.sbom_version`, `Document.lifecycles` and `Document.tool_versions` in
  the IR, with parser support for both CycloneDX shapes. Four of the new
  elements had no field to read: CycloneDX carries the BOM revision at the
  document root and the generation phase in `metadata.lifecycles`, and tool
  versions were being dropped on the floor by the metadata mapping. Without
  these the corresponding rules would have been unsatisfiable by construction.
- SPDX 2.x tool versions are recovered from the `Tool: name-version` creator
  convention, and left unset when the creator omits the version rather than
  guessing.

### Changed
- `ntia-min-elements` and `cisa-2025-min` now say in their names and sources
  that they are superseded. Neither is retrofitted: procurement language written
  against the 2021 document needs a check that still means 2021, and the 2025
  draft is kept so a run from its comment window stays reproducible.
- `cisa-2026-min` is standalone rather than extending `ntia-min-elements`.
  Inheriting would put 2021 rule ids and 2021 citations inside a report claiming
  conformance with the 2026 document.

### Fixed
- **`eu-cra-annex-vii` cited clauses that do not exist and has been withdrawn.**
  It carried rules citing "CRA Annex VII §8(a)", "§8(b)" and "§8(c)". Annex VII
  point 8 of Regulation (EU) 2024/2847 is a single sentence with no sub-points:
  "where applicable, the software bill of materials, further to a reasoned
  request from a market surveillance authority provided that it is necessary in
  order for that authority to be able to check compliance with the essential
  cybersecurity requirements set out in Annex I." It names no data field and is
  a disclosure trigger, not a content specification. The eight data-field rules
  were not derived from the Regulation.
- **New `eu-cra-annex-i` profile** encoding Annex I Part II(1), the clause that
  does constrain SBOM content: "identify and document vulnerabilities and
  components ... including by drawing up a software bill of materials in a
  commonly used and machine-readable format covering at the very least the
  top-level dependencies of the products." That yields four rules. The removed
  author, timestamp, licence and hash rules have no basis in the CRA and are not
  recited under a CRA citation.
- The `eu-cra-annex-vii` id resolves to an empty, clearly-labelled withdrawn
  profile rather than being deleted, so it stays loadable for anyone with it
  pinned in CI while asserting nothing.
- **Every remaining profile was re-read against its published source.** The
  documents, with SHA-256 checksums, are listed in `docs/sources/`. Corrections:
  - `bsi-tr-03183-v2.1` cited §6.1, §6.2, §6.3 and §7. In TR-03183-2 v2.1.0 §6.1
    is "Licence identifiers and expressions", §6 has no 6.2 or 6.3, and §7 is
    "Transitional system". Required data fields are §5.2.1 (SBOM itself) and
    §5.2.2 (per component); "other unique identifiers" is §5.2.4 and conditional.
  - `bsi-tr-03183-v2.1` no longer gates on a digital signature. The Guideline
    mentions signing once, in Appendix 8.1.15: "Ideally, SBOMs should be
    digitally signed." `require_signature` failed every unsigned SBOM against a
    requirement BSI never made; it is a SHOULD rule now. The `bsi-tool` rule is
    removed: §5.2.1 Table 2 has exactly two fields, Creator and Timestamp.
  - `openchain-telco-v1.1` cited §4 for all seven rules. §4 is "Conformant
    notice"; the required SPDX elements are §3.2. PURL drops to SHOULD, matching
    "A package SHOULD be identified by a Package URL (PURL)".
  - `cert-in-v2.0` cited §5 in its rules and §6 in its sources. The minimum
    elements are §4.1 Table 5 and §4.2, in the v2.0 guidelines of 2025-07-09.
  - `ntia-min-elements` had Supplier Name at MUST_WHERE_AVAILABLE. The 2021
    report lists seven data fields flat with none marked optional; it is MUST.
- **`hash_coverage` was computed and then read by nothing.** The signal was
  gathered on every run and referenced by no scoring category, so hash quality
  could not affect any score. It now feeds Accuracy, and counts only well-formed
  digests rather than mere presence. Documents carrying hashes will see Accuracy
  move as a result.
- Coverage gaps are stated in the profiles rather than left implicit.
  `openchain-telco-v1.1` covers seven of the elements §3.2 requires and does not
  reject CycloneDX, which §3.1 forbids. `cert-in-v2.0` covers eight of the
  twenty-one fields in Table 5. Both name the missing fields in a comment,
  because a silent gap reads as coverage.
  - `fedramp-sbom` carried eight rules citing "FedRAMP SBOM: Author of SBOM Data
    (NTIA-aligned)" and similar. FedRAMP publishes no SBOM data field list; the
    parenthetical was the tell that the rules were the NTIA list relabelled. The
    obligation is real but delegated: EO 14028 §4(e)(vii) requires an SBOM and
    §4(f) directs Commerce, through NTIA, to publish the minimum elements, which
    is the document CISA now maintains. The profile is a composition now,
    inheriting `cisa-2026-min` and adding nothing, so findings carry `cisa26-*`
    ids citing the document the requirement actually comes from.

### Added
- The profiles guide now states how much of each standard a profile actually
  covers, for the two where a PASS is narrower than the standard: `cert-in-v2.0`
  checks 8 of 21 fields (13 of the rest are organisational judgements no SBOM
  carries), and `openchain-telco-v1.1` cannot reject a non-SPDX document even
  though §3.1 requires SPDX.
- **`hash_wellformed` validator.** Checks each digest is hexadecimal and the
  right length for its declared algorithm. `hash_algorithm_in_set` only inspects
  algorithm names, so a component declaring SHA-256 with a value of `zzz` passed
  every hash rule. The CycloneDX schema rejects non-hex but its regex accepts any
  valid digest length, so a SHA-256 carrying a 40-character value was
  schema-valid and still wrong; SPDX has no equivalent constraint. A truncated or
  mismatched digest is worse than a missing one, because it looks like an
  integrity check while verifying nothing. Wired into `cisa-2026-min` and
  `bsi-tr-03183-v2.1`, the two profiles that check hashes.
- **`hash_consistency` scoring signal**, feeding Consistency. Components that
  carry hashes should carry the same algorithms; a file that is half SHA-512 and
  half SHA-1 usually means two generators were merged without reconciliation.
- `docs/sources/` records every document a profile was transcribed from, with
  version, retrieval URL and SHA-256. Documents whose terms permit it are held
  in the repository (CISA 2026 and NTIA 2021 as US Government works, the
  OpenChain Telco Guide under CC0, CRA extracts under Decision 2011/833/EU).
  BSI and CERT-In reserve copyright without a reuse grant, so those are recorded
  by URL and checksum rather than redistributed.

### Notes on severity
- Every rule in `cisa-2026-min` is MUST. Appendix A is a flat table of seventeen
  data fields and the document never marks one optional, recommended,
  conditional or where-available; those words do not appear in it. Most real
  SBOMs fail this profile today, which is the finding rather than a defect. The
  quality score already carries the gradient: a document can read FAIL at 88/100
  and know it is close.
- Where the document lets an author say a value is unknown, that is encoded with
  a new `declared` validator rather than a weaker severity. `declared` passes on
  an explicit NOASSERTION/NONE and fails on silence, which is what "Explicitly
  Identifying Unknown Information" asks for. `present` cannot express it: it
  treats an explicit null as absence and fails it.
- SPDX 2.x cannot express SBOM Version or SBOM Generation Context, so SPDX 2.x
  documents fail `cisa-2026-min` on those two rules. That is a true and
  actionable statement about the format (move to CycloneDX 1.5+ or SPDX 3.0),
  not a reason to downgrade the rules until they stop being reported.

## [2.0.0] - 2026-07-30

The relaunch: the three standalone Xpertians packages (`ossbomer-schema`,
`ossbomer-conformance`, `ossbomer-oslc`) are consolidated into a single
profile-driven `ossbomer` distribution.

### Added
- Unified `ossbomer validate --profile <name> ... --file <sbom>` CLI; `--profile`
  is repeatable and each profile yields an independent verdict + quality score.
- Profile format and loader binding schema minima + conformance rules + license
  policy in one YAML file, composable via `extends` / `excludes`, with private
  overlay search paths (`--profile-path`, `OSSBOMER_PROFILE_PATH`).
- Profile catalog: NTIA, CISA 2025, EU CRA (Annex VII), BSI TR-03183 v2.1,
  India CERT-In v2.0, OpenChain Telco v1.1, FedRAMP, and a net-new AIBOM v0.1.
- Four license-policy profiles — `license-distribution`, `license-mobile`,
  `license-saas`, `license-internal` — so the ospac-backed license layer works
  out of the box and can be copied as a starting point.
- Canonical SBOM intermediate representation and parsers built on
  `cyclonedx-python-lib` and `spdx-tools`; iterate per component and per dependency.
- Pluggable validator registry (presence, non-placeholder, RFC 3339 UTC, SPDX
  license expression, PURL, SemVer/CalVer, hash-algorithm-in-set,
  format-version-at-least, format-version-not-deprecated, references-VEX,
  signed-with-x509,
  dependency-completeness, known-unknowns) plus an entry-point plugin hook.
- Five-category quality scoring (Completeness, Accuracy, Consistency, Provenance,
  Freshness), weighted per profile, never blended across profiles.
- Reporters: console, JSON, and SARIF (one run per profile).
- Multi-version fixture corpus and a schema version matrix test suite.

### Changed
- **The OSLC layer is now backed by `ospac`.** Declared licenses are evaluated
  against an ospac policy for a **use case** the profile names — `mobile`,
  `saas`, `internal`, `commercial` — so the same license can be allowed in one
  context and denied in another. Adopters can point a profile at their own ospac
  policy directory via `policy_path`. The previous inline `license_rules`
  allow/deny list remains as an override layer applied after the engine, and
  still works with no engine and no optional dependency. `ospac` stays an
  optional extra; a profile that declares `engine: ospac` without it installed
  now fails with exit 2 rather than silently skipping the license layer.
- SPDX license *expressions* are evaluated with their real semantics: `OR`
  resolves to the least restrictive operand, `AND` to the most restrictive.
- Schema validation is now **version-aware**: documents are validated against
  their detected version instead of a hardcoded schema.
- License stays **Apache-2.0**, matching the previous PyPI `ossbomer` 0.1.4. An
  earlier step in the relaunch had moved it to MIT; that is reverted, so 2.0.0 is
  not a relicensing event for anyone already depending on 0.1.4.

### Fixed
- `schema.deprecated_versions_forbidden` is now enforced. It was parsed and then
  ignored, while `eu-cra-annex-vii` and `bsi-tr-03183-v2.1` both declared it — so
  two shipped profiles asked for a check that never ran. The retired set is
  profile data (`schema.deprecated_versions`) with an overridable default, rather
  than a judgement frozen in the engine.
- `ossbomer-schema` printed a raw traceback for an unreadable file, and used exit
  `1` for "could not process" where the other commands use `2`. All four commands
  now share one exit-code convention.
- JSON output now carries each profile's `sources` — the standard it encodes. The
  field was parsed from all twelve profiles and then discarded, so a compliance
  report never said what it was claiming compliance *with*.
- SPDX relationships pointing at `NONE` or `NOASSERTION` were added to the
  dependency graph as non-string sentinel objects, where `dependency_completeness`
  then compared them against real component refs. They state that no relationship
  is asserted, so they are no longer treated as edges.
- A validator spec written as a mapping without a `name` key reached the registry
  as `None` and reported `Unknown validator: None`, which did not say which rule
  was malformed. It now raises `ProfileError` naming the offending spec.
- `Component.identity` ended its fallback chain with an f-string, which is always
  truthy, making the `bom_ref` and `<unknown>` fallbacks unreachable. Components
  carrying only a bom-ref were labelled `None@None` in issue locations.
- CycloneDX document authorship was read only from `metadata.tools`, so
  `metadata.authors` and `metadata.manufacturer` were ignored. Any CycloneDX SBOM
  authored by a person or an organization rather than generated by a tool failed
  the "author of SBOM data" requirement, which is a MUST in seven of the eight
  shipped profiles. `creators` now holds people, organizations and tools — mirroring
  the SPDX mapping — and `tools` remains the tool-only subset.
- CycloneDX JSON was always validated against the 1.4 schema regardless of the
  document's declared version.
- SPDX/CycloneDX XML validation was stubbed to always report "Valid".
- The `ossbomer-conformance --rules` flag was silently ignored.

### Removed (breaking, for the legacy per-layer commands)
- **The standalone conformance implementation.** It kept its own rule table and
  read only `metadata.component` — the root component the SBOM *describes* — so
  it never looked at the component inventory. A document with unversioned,
  unidentified components was reported as NTIA-conformant. It also exited `0`
  regardless of the result, so it could not gate CI, and its `author` mapping
  only understood the pre-1.5 CycloneDX `tools` shape, producing false failures
  on 1.5+ documents. `ossbomer-conformance` is now a front-end over the profile
  engine.
- **The standalone license checker** and its bundled 400 KB `license_rules.json`,
  superseded by the ospac-backed layer. `ossbomer-oslc --use-case` now selects a
  license profile.
- `--rules` and `--license-rules`, whose file formats no longer exist. They now
  error, naming the replacement, rather than being silently accepted.

### Removed
- The bundled 136 MB OSSA advisory dataset and `PackageRiskAnalyzer` (license
  classification moves to `ospac`; package risk to a forthcoming open PURL API).
- ~2 MB of bundled SPDX/CycloneDX schema files (the parser libraries carry their own).

[Unreleased]: https://github.com/SemClone/ossbomer/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/SemClone/ossbomer/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/SemClone/ossbomer/releases/tag/v2.0.0
