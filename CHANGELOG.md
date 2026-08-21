# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.4.0] - 2026-08-20

### Changed
- `Callable` is imported from `collections.abc` rather than `typing`, which the
  raised floor makes available.

### Removed
- Python 3.9 support. `requires-python` is now `>=3.10`.

  It had become a correctness problem rather than a maintenance one. ospac
  requires Python 3.10 from 1.4.3, so a 3.9 environment resolved to ospac 1.2.3
  and got **712 license mappings against 1471** on any newer interpreter — the
  same SBOM, the same profile, licenses reported unresolvable on one machine and
  resolved on another, with nothing said about why. Supporting an interpreter
  that has been end-of-life since 2025-10-31 was not worth results that depend
  on which Python installed the dependency.

  The `[oslc]` extra is floored at `ospac>=1.4.3` accordingly. That floor was
  unreachable while 3.9 was supported, which is what let the divergence exist.

  3.9 users can pin `ossbomer==2.3.1`, which is the last release supporting it.

## [2.3.1] - 2026-08-20

### Added
- A declaration that names a licence without identifying it is now its own
  outcome rather than plain "unresolved". "GNU LESSER GENERAL PUBLIC LICENSE,
  Version 2.1" names the licence and the version and still is not an
  identifier, because `-only` versus `-or-later` is the copyright holder's
  grant and the licence's own name does not carry it. Resolving either way
  would assert something the document never said.

  The list of which names are ambiguous is licence data, so it is marked as a
  fallback pending [ospac#89](https://github.com/SemClone/ospac/issues/89) — as
  are the curated alias and refuse-to-resolve tables beside it. ospac
  regenerates from SPDX releases and already supplies 1471 of the 1505 mappings
  in use; the 34 held here are the ones it does not carry yet. A hand-held list
  is not wrong when written, it is wrong two SPDX releases later, quietly, and
  differently in every consumer keeping its own copy.

  Both remain unresolved, but the finding now says which distinction is
  missing — "it does not say whether later versions are permitted, so it could
  be LGPL-2.1-only or LGPL-2.1-or-later" — because that sends a reader to a
  different fix than an unrecognised name does.

### Fixed
- A licence declared as prose rather than an SPDX identifier was reported as
  unresolvable, so a document naming its licence perfectly clearly counted as
  not having declared one. Maven-sourced SBOMs carry the name from a POM's
  `<licenses>` block far more often than the identifier: "The Apache Software
  License, Version 2.0" rather than `Apache-2.0`.

  The same licence is written several ways across POMs — with and without a
  leading "The", with "Version 2.0" or ", version 2.0" or a bare "2.0", with
  "Software" in the middle or not. Listing every spelling would be an
  open-ended table, so the spelling is normalised away and matched against the
  alias table that already existed. This is normalisation, not inference: the
  alias still has to be there, and nothing here makes "BSD" mean
  `BSD-3-Clause`.

## [2.3.0] - 2026-08-20

### Added
- `omb-m-26-05`, encoding OMB Memorandum M-26-05, *Adopting a Risk-based
  Approach to Software and Hardware Security* (2026-01-23). The memorandum
  rescinds M-22-18 and M-23-16 and replaces their government-wide floor with
  agency discretion, so it mandates no SBOM: agencies "may also choose to adopt
  contractual terms" requiring a producer to supply one on request. A PASS
  therefore does not mean "M-26-05 compliant", because no such state exists. It
  means an SBOM produced under a term an agency chose to adopt carries the
  fields the memorandum pointed that agency at. The obligation lives in the
  contract.

  The memorandum names no data field, so the profile composes rather than
  transcribes, as `fedramp-sbom` does. It extends `cisa-2025-min` and adds no
  rules of its own; findings report `cisa-*` and `ntia-*` rule ids citing the
  documents the fields actually come from. Inventing `omb-*` ids would assert
  clauses that a two-page memorandum does not contain, which is the defect that
  got `eu-cra-annex-vii` withdrawn.

  It extends the 2025 draft rather than `cisa-2026-min` because M-26-05 cites
  "CISA, 2025 Minimum Elements for a Software Bill of Materials (SBOM)
  (published in draft form on Aug. 22, 2025)" — one document, by date, in a list
  the memorandum introduces as material agencies "can reference ... for
  additional information and options". That is a dated citation, not the open
  delegation EO 14028 §4(f) makes and which lets `fedramp-sbom` track whatever
  CISA publishes next. CISA replaced that draft on 2026-07-29 and the memorandum
  has not been reissued; following the drift silently would fail a procurement
  written against M-26-05 as issued on fields its own reference document never
  listed. Use `cisa-2026-min` directly if your contractual term names the 2026
  document.

  Footnote 1's instruction that a cloud platform SBOM cover "the runtime
  production environment" is deliberately not encoded. It constrains what the
  SBOM is *of*, not what fields it carries, and nothing in an SBOM file
  reliably declares its subject.

- The memorandum itself, at
  `docs/sources/documents/omb-m-26-05-risk-based-approach-software-hardware-security.pdf`,
  redistributable as a US Government work under 17 U.S.C. §105, with its
  SHA-256 recorded in the source index alongside every other cited document.
- `fields` on a rule, for a requirement a document may satisfy in more than one
  way. Lists IR attributes in precedence order and hands the validators the
  first one carrying a real value; null tokens such as `NOASSERTION` are skipped
  rather than shadowing a usable value behind them. `field` is unchanged and
  remains the single-attribute form.
- `cpe_wellformed`, checking CPE names against NIST IR 7695's own regular
  expressions for the two bindings: the 2.3 formatted string (§6.2.2) and the
  2.2 URI (§6.1). Transcribed rather than paraphrased, because structural checks
  written by hand admitted malformed names one class at a time — any `part`
  value, then empty attributes, then attribute text containing spaces. A
  component count and a `part` check are not the grammar. One documented
  deviation: the published 2.2 expression pins the scheme's first letter to
  lower case while allowing either case for the other two, so `CPE:/a:vendor` is
  rejected as written; URI schemes are case-insensitive (RFC 3986 §3.1) and this
  matches the whole scheme either way. It checks form, not existence — whether a
  vendor and product name something real is not a question an SBOM validator can
  answer.
- `component_identifier`, for clauses accepting either identifier. Decides the
  form per value from its prefix, so a CPE is validated as a CPE and a purl as a
  purl.
- A file inventory in the IR, and a `file` rule scope to target it. The IR
  modelled documents and components and nothing else, so an SBOM's file entries
  and the checksums on them were discarded at parse time: SPDX 2.3 §8.4 makes
  `FileChecksum` mandatory on a file entry, and no rule could say so because
  there was nothing to point at.

  `Sbom.files` is populated from SPDX 2.x's `files` section in all four
  encodings, from SPDX 3.0's `software_File` nodes including their
  `verifiedUsing` digests, and from CycloneDX components of `type: file`. The
  CycloneDX ones are mirrored rather than moved: taking them out of `components`
  would change what every existing component rule sees. Nested components are
  walked, since CycloneDX writes a file belonging to a library inside that
  library's own `components`; `components` itself stays top-level, as it has
  always been, because making it recurse would hand every existing component
  rule entries it has never judged. A `metadata.component` of `type: file`
  counts as an entry too — a BOM describing a single file
  declares one, and reporting "no file inventory" for it would be wrong. It
  joins the inventory only; the described subject is deliberately not a
  component here and stays out of that list.

  A `file` rule answers two different questions and only one can be a violation.
  A document with no inventory reports `WARN` whatever the rule's severity —
  the section is optional in both formats and a dependency-level SBOM
  legitimately has none, so deriving that from the severity would make a `MUST`
  file rule fail every SBOM that does not enumerate files. Within an entry the
  severity governs as usual, so a `MUST` rule still fails a file whose checksum
  is missing.

  No bundled profile carries a file rule yet, so the file inventory itself
  changes no verdict: every bundled profile over every corpus document produces
  identical findings, scores and verdicts.

  The SPDX 3.0 fixes below are the exception, and they are not additive by
  design. A document whose nodes spell their type as `@type` previously parsed
  to nothing and was reported schema-invalid; it now parses, so its schema
  verdict flips to PASS and its score moves — downward, because rules finally
  see the components they were always meant to judge. That is the fix working,
  not a regression, but it is a verdict change and should not be described as
  anything else.

  This is the parser and engine work; rules follow per profile, where a clause
  actually calls for one.

### Changed
- A rule naming an unknown `scope` is refused when the profile loads, rather
  than silently producing no findings. Previously a typo made the rule vanish,
  which reads as a clean pass; `file` and `files` are one keystroke apart. This
  can turn a private overlay that loaded before into a load error, which is the
  point — it was never running the rule it appeared to declare.

### Fixed
- Components identified only by a CPE were reported as having no identifier, and
  on SPDX input a CPE was never read at all. Two defects that hid each other.

  The SPDX parser walked `external_references` looking for `purl` and stopped
  there, so `Component.cpe` was `None` for every SPDX document in every
  encoding, while the CycloneDX path populated it. The same component expressed
  in the two formats produced different IR. SPDX 2.3 §7.11.2 carries CPEs in
  that same list under the `cpe22Type` and `cpe23Type` reference types; both are
  now read, and a package may declare a purl and a CPE without either lookup
  ending the other.

  `bsi-component-identifier` matched on `field: purl` while citing BSI
  TR-03183-2 §5.2.4, "other unique identifiers (CPE or purl), if it exists". A
  component carrying a valid CPE and no purl failed a requirement it met, and
  the rule's own `purl_wellformed` would have rejected the CPE had it reached
  it. A check narrower than the clause beside it is the defect this catalog
  exists to avoid.

  Only SPDX documents whose packages declare CPEs change verdict, and only for
  that rule: a CPE-only component moves from a spurious WARN to PASS. Nothing in
  the test corpus was affected, since no fixture declared a CPE — which is how
  this survived.

- `MUST_WHERE_AVAILABLE` failed rules whose field holds a container rather than a
  string. The severity exists to excuse a document that never declared the data,
  and availability was decided with an inline null test that counted an empty
  list or dict as declared. `cisa-component-hash` therefore reported FAIL for a
  component carrying no hashes at all — the exact case "where available" is
  there to permit — and `cisa-2025-min`, plus anything extending it, scored it
  as a violation. Absent now reports WARN; a hash that is present and outside
  the required set still fails. Predates the identifier work above and was found
  while reviewing it.
- `present` passed a mapping field that was empty. `_as_list` had no branch for
  a mapping, so `hashes: {}` fell through to the catch-all, came back as `[{}]`
  and read as populated — a component or file carrying no hashes at all
  satisfied a `present` check. A mapping now contributes its values, which is
  what a rule asking whether a hash is present means. No bundled profile paired
  `present` with a mapping field, so no shipped rule was affected; the natural
  spelling of a file checksum rule is the first thing that needed it.
  `known_unknowns_declared` had been working around this locally since it was
  written.

  The engine's availability test and `present` now share one implementation
  (`validators.has_value`). They asked the same question in three places and
  drifted twice: an inline null check counted an empty container as data, and a
  key-based mapping check counted `hashes: {"sha256": ""}` as data while
  `present` called it absent.
- SPDX 3.0 nodes spelling their type and id as `@type` and `@id` parsed to
  nothing at all. The reader matched `"type"` and `"spdxId"` only, so such a
  document produced no components, no files and no creation info and was
  reported as an SBOM that declared nothing rather than one that could not be
  read. Both spellings are accepted now — for packages and the document node as
  well as files — a full IRI is trimmed to its class name, and a `@type` list
  is read in full rather than by its first entry, which had turned
  `["…/Core/Element", "…/Software/File"]` into `Element` and skipped the node.
  The schema gate shares the same normaliser: it built its type set from
  `"type"` alone, so a document that parsed correctly was still reported
  "@graph contains no SpdxDocument/CreationInfo element" for a graph that
  plainly had both. Reading a shape the gate then rejects is not support.

  A 3.0 file's `software_copyrightText` reaches the IR too, since the SPDX 2.x
  and CycloneDX paths both fill `copyright` and the same file should not answer
  differently by format. `licenses` stays empty on 3.0: licensing there is a
  relationship to a separate license element rather than a property, which
  nothing resolves yet — components are in the same position.

  {: .note }
  This is not full expanded-JSON-LD support. A document in the fully expanded
  form — a top-level array, properties keyed by IRI, values boxed in `@value` —
  is still rejected at detection, before any of this runs. Predates the file
  inventory; found while adding it.
- SPDX 3.0 hash algorithm names containing an underscore were truncated.
  Trimming the `hashAlgorithm_` prefix by splitting on every underscore left
  `sha3_256` as `256`, a different algorithm entirely. Only the prefix comes off
  now, and `hash_algorithm_in_set` compares names with the underscore stripped
  as well as the hyphen — it stripped only the hyphen, so `sha3_256` and
  `SHA3-256` still compared unequal and a file carrying a valid SHA3-256 digest
  failed a rule that allows SHA3-256.
- A CycloneDX component whose `type` is not a string crashed the parser with an
  `AttributeError` instead of reaching the schema gate, which is what exists to
  report it. Introduced with the file inventory, which selects components by
  `type`; a traceback is a worse answer than a schema failure.
- The CycloneDX mapper raised on a malformed document instead of reaching the
  schema gate. The schema promises a shape; the document is not obliged to keep
  that promise, and this parser is not what reports the breach —
  `validate_schema` is, and it only runs if parsing survives to call it. A junk
  field therefore replaced a usable "your SBOM is invalid because X" with a
  traceback and exit 2, on precisely the input a validator exists to be handed.

  Ten sites crashed: `metadata`, `components` and `dependencies` at the top
  level; `properties`, `licenses`, `hashes` and nested `components` within a
  component; a `dependsOn` ref that was not a string, which became a dict key;
  and `bom-ref` or `purl` holding a container, which raised inside
  `dependency_completeness` — past the parser and past the schema gate both.
  Every container is now read through one defensive helper, and every scalar the
  IR types as text through another. A number is kept rather than dropped, since
  `version: 1.0` written as a float is a real generator mistake and the value is
  still the version.

  The SPDX 3.0 reader owed the same contract and got the same pass: `@graph` and
  `createdBy` both raised when they held something other than a list. It is
  best-effort about shapes it understands, which is not licence to raise on
  shapes it does not.

  The test is generative rather than a list: 430 documents across both readers,
  every field they read against ten wrong types, asserting only that parsing
  returns and a verdict is reached. Enumeration looked finished long before it was — three
  of these were fixed one at a time as review happened to reach them, and the
  generative test found two more the moment it ran.
- A CycloneDX hash entry whose `alg` is not a string — `null`, an object, or a
  non-object entry entirely — crashed the parser the same way. That one predates
  the file inventory and applied to every component; the inventory made it
  newly reachable through `metadata.component`, which nothing had inspected
  before. Both mappers now share one tolerant reader, so a document cannot crash
  on the copy that was not fixed. A valid digest alongside a malformed one is
  still kept.

## [2.2.2] - 2026-08-02

### Fixed
- `rfc3339_utc` did not implement RFC 3339. It delegated its grammar to
  `datetime.fromisoformat`, which implements ISO 8601, a superset, and then
  looked for a timezone designator by substring. It therefore returned PASS for
  values its own message called invalid: a bare date with an offset
  (`2026-01-01+00:00`), a time without seconds (`2026-01-01T00:00+00:00`), and
  an offset carrying seconds (`2026-01-01T00:00:00+00:00:00`). A false PASS is
  the wrong direction for a conformance tool, since it reports a malformed
  document as meeting a requirement it does not meet.

  The same check was also too strict, rejecting the lower case `t` and `z`
  forms that section 5.6 explicitly permits, and impossible instants such as
  `2026-02-30T00:00:00Z` now fail rather than being reported against whatever
  the interpreter happened to accept. Leap seconds (section 5.7) are accepted,
  but only where one can occur: `time-second` allows 60 under the leap second
  rules, not as a free 61st second of any minute, so once the offset is taken
  off the instant has to be 23:59:60 on the last day of a UTC month.

  Digit fields are ASCII, as the ABNF `DIGIT` is. Python's `\d` also matches
  the decimal digits of other scripts, and `int()` is equally willing to
  convert them, so `٢٠٢٦-٠١-٠١T٠٠:٠٠:٠٠Z` had been a valid timestamp.

  Verdicts no longer depend on the interpreter either: before 3.11,
  `fromisoformat` rejected fractional seconds of any length but 3 or 6 digits,
  so `2026-01-01T00:00:00.5Z` passed on some supported Pythons and failed on
  others.

  A leap second on the first or last representable date has no neighbouring
  day to step to when asking whether it ends a month, and the scorer calls
  this validator directly, outside the engine's guard. `9999-12-31T23:59:60Z`
  therefore ends one rule rather than the run.

  No document in the test corpus changes verdict, including the real-world
  SBOMs under `tests/conformance/`: every generator in it emits conformant
  timestamps.

## [2.2.1] - 2026-08-02

### Fixed
- Every conformant SPDX 2.x document failed its profile's timestamp rule.
  SPDX section 6.9 defines `created` as UTC, so spdx-tools parses it into a
  naive datetime and drops the `Z`; formatting that value produced a string
  with no offset, which `rfc3339_utc` was then right to reject. A CycloneDX
  document carrying the identical timestamp passed, so the verdict described
  the format rather than the document. Affected the timestamp rule in
  `ntia-min-elements`, `cisa-2026-min`, `cert-in-v2.0`, `bsi-tr-03183-v2.1`,
  `openchain-telco-v1.1` and `aibom-v0.1`, and the scorer's freshness signal
  on every profile. SPDX 2.x scores rise 4 to 8 points across the fixtures;
  SPDX 3.0 was never affected, since its parser keeps the raw string.
- The profiles guide described `fedramp-sbom` as "FedRAMP SBOM requirements".
  The profile was renamed away from that wording precisely because FedRAMP
  publishes no SBOM requirements, so the catalog table was still asserting the
  claim the code had stopped making.
- `tests/conformance/test_sbom.cyclonedx.1.4.xml` could not be loaded by any
  profile. Its `dependencies` block referenced a `bom-ref` that no component
  declared, so `cyclonedx-python-lib` refused the document. Its JSON twin had
  the same defect and only loaded because the JSON path does not check
  referential integrity. Both carry `bom-ref` now and produce identical results.
- `test_docs_match_code.py` compared only whether a profile id appeared in the
  guide, so a table could name every profile and still describe one wrongly. It
  compares the label against the profile's own name now.

## [2.2.0] - 2026-07-31

### Fixed
- Console output no longer contains em dashes. Findings separated the rule id
  from the message with one, profile display names for the four `license-*`
  profiles carried one, and the license layer joined a remediation hint with one.
  All are plain punctuation now.
- The README example showed output the tool does not produce. It claimed a
  profile name of "NTIA Minimum Elements for an SBOM" while the tool prints
  "(2021; superseded by cisa-2026-min)" after it. The example is copied from a
  real run now, and uses `cisa-2026-min` rather than steering readers at a
  superseded profile.
- The README's exit code description omitted that a withdrawn profile exits 2.
- Em dashes removed from the documentation, including three sample output blocks
  in the getting-started guide that showed the old separator and so no longer
  matched what the tool prints.

### Added
- The README describes license normalization, which shipped in 2.1.0 and was not
  mentioned anywhere a PyPI visitor would see.

## [2.1.0] - 2026-07-30

This release changes rule ids and verdicts, not only the profile catalog.
Overlays that exclude a rule by id, and CI gates that act on a verdict, will see
different results than they did on 2.0.0. The specifics are immediately below.

### Changed behaviour
None of this removes a check that was doing useful work. Every item is a
correction of something that was wrong, so a verdict that changes here was
wrong before rather than right.

- **`eu-cra-annex-vii` refuses to run.** Its eight rules checked data fields
  against CRA Annex VII point 8, which is one sentence naming no data field, so
  all eight were invented. It exits 2 with the reason and points at
  `eu-cra-annex-i`. Emptying the rules was tried first and was worse: zero
  findings computes to PASS, so a profile withdrawn for being wrong started
  reporting success on documents it had previously failed.
- **`fedramp-sbom` got stricter and gained a source.** Its eight rules listed
  data fields FedRAMP never published. It composes `cisa-2026-min` now, so eight
  invented checks became seventeen real ones, reported under `cisa26-*` ids
  because that is where the requirement comes from.
- **`bsi-tr-03183-v2.1` stopped requiring things BSI does not.** The signature
  gate traced to an appendix line reading "ideally, SBOMs should be digitally
  signed", and `bsi-tool` had no basis at all: the document-level table has two
  fields, Creator and Timestamp. Unsigned documents that failed now pass, which
  is the correct answer.
- **`ntia-min-elements` treats Supplier Name as required.** The 2021 report lists
  seven data fields flat with none marked optional, so documents that warned now
  fail.
- **`openchain-telco-v1.1` treats a PURL as recommended.** The Guide says a
  package should have one, so it warns rather than fails.
- **Seventeen check names changed or went with the profiles that invented them.**
  Switching a check off by name in an overlay, or suppressing one by name in code
  scanning, needs the new name. `excludes` skips names it cannot find rather than
  complaining, so it will not say anything.

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
- **Declared licenses are normalized to SPDX at parse time.** CycloneDX offers
  three license slots and the flat `licenses` list collapsed them, so free text
  from `license.name` was reported as bad expression syntax while a valid
  expression sitting in that same slot passed silently. `Component` now carries
  `license_declarations` recording the raw text, the slot, the normalized form
  and the method. Handled: `+` suffixes, `-or-later`, lowercase `or`/`and`/
  `with`, nesting, npm's `||`, and `/`, `,`, `;` separators. Lists resolve to
  `AND` rather than `OR`, because policy takes the least restrictive operand of
  an `OR` and mis-reading a list would under-report obligations.
- Family names (`BSD`, `GPL`, `Apache`, `Public Domain`) are refused rather than
  guessed. Bare `GPL` needed an explicit denylist entry: the parser resolves it
  to `GPL-1.0-or-later`, which nobody writing `GPL` today means.
- New `license_spdx_normalized` and `license_in_spdx_field` validators, wired
  into `cisa-2026-min` and the four `license-*` profiles. The second reports a
  valid expression declared in the free-text slot, which a consumer reading only
  `expression` and `license.id` would miss entirely.
- License name mappings are read from ospac when it is installed, rather than
  re-curated here. ospac regenerates a record per SPDX identifier from SPDX
  releases, so its ~712 official long names stay current without a release here.
  Read through `ospac.license_aliases()` if that function exists, otherwise from
  its shipped records; ospac remains optional and strictly additive, since
  normalization is used by every profile while ospac is only the `[oslc]` extra.
- The tables extend without editing the package, via
  `OSSBOMER_LICENSE_ALIASES` files or an `ossbomer.license_aliases` entry point.
  Overlays win on conflict in both directions.
- Policy now receives normalized identifiers. Previously `"Apache 2"` reached
  ospac verbatim and was evaluated as an unknown license.
- **A validator can no longer end a run.** SBOM fields carry whatever the
  generator put there, and third parties register their own validators through
  the `ossbomer.validators` entry point, so not all code in that loop is
  auditable here. An exception raised while evaluating a value now becomes a
  FAIL finding naming the validator and the error, instead of exiting 2. One
  malformed field in one component costs that component a finding, not the whole
  report. `ProfileError` and an unknown validator name still propagate: those
  are configuration errors, and reporting them as findings would blame the
  document for the operator's mistake.
- `hash_algorithm_in_set` raised `AttributeError` when a hash entry used a null
  algorithm key. Algorithm names are coerced with `str()` before comparison.
- **SPDX parsing follows the bytes, not the filename.** `detect_file` reads the
  content, but `spdx_tools`' `parse_anything` dispatches on the extension, so the
  two could disagree. A tag-value document named `.json` was detected correctly
  as `spdx 2.2 tagvalue` and then failed with "Expecting value: line 1 column 1",
  while the same bytes named `.spdx` scored 74. SBOMs arrive from APIs, build
  artifacts and downloads with wrong or absent extensions. `parse_anything` is
  still tried first, since it distinguishes `.rdf.xml` from `.xml`, and the
  detected encoding is the fallback.
- **The license validator no longer crashes on strings real SBOMs carry.**
  `license_expression.validate()` raises `AttributeError` internally on
  `"MIT (http://mootools.net/license.txt)"`, which appears in the ProtonMail
  SBOM. Six profiles died with exit 2 on that document. A parser that explodes
  on a value is still saying the value is not a valid expression, so it is
  reported as a finding rather than taking the run down. The scorer already
  guarded this; the validator did not.
- **The SPDX licensing index is built once per process instead of per component.**
  `get_spdx_licensing()` rebuilds the whole index on every call and caches
  nothing. On an 883-component SBOM it was called 1739 times and accounted for
  28.7s of a 43.4s run. Validating that document with `cisa-2026-min` went from
  20.5s to 0.8s.
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

### Documentation
- The validator table in the CLI reference listed fourteen while eighteen ship,
  so `declared`, `hash_wellformed`, `license_spdx_normalized` and
  `license_in_spdx_field` were undiscoverable for anyone reading the docs rather
  than running the command. It is now a table saying what each one passes on.
- New reference for what `field` can name, per scope. There was none, and 2.1.0
  added four IR fields (`sbom_version`, `lifecycles`, `tool_versions`,
  `license_declarations`) with nowhere to describe them.
- `OSSBOMER_LICENSE_ALIASES` is listed alongside `OSSBOMER_PROFILE_PATH` in a new
  environment variable table.
- Exit code 2 now documents the withdrawn-profile case.
- `tests/test_docs_match_code.py` fails when a validator, profile or environment
  variable exists in code but not in the docs. The validator list had already
  drifted once; this is how it stops.

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

[Unreleased]: https://github.com/SemClone/ossbomer/compare/v2.4.0...HEAD
[2.4.0]: https://github.com/SemClone/ossbomer/compare/v2.3.1...v2.4.0
[2.3.1]: https://github.com/SemClone/ossbomer/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/SemClone/ossbomer/compare/v2.2.2...v2.3.0
[2.2.2]: https://github.com/SemClone/ossbomer/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/SemClone/ossbomer/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/SemClone/ossbomer/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/SemClone/ossbomer/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/SemClone/ossbomer/releases/tag/v2.0.0
