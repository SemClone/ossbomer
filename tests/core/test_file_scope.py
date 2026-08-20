"""The file inventory: parsing it, and rules that target it.

The IR modelled documents and components and nothing else, so an SBOM's file
entries and the checksums on them were discarded at parse time. SPDX 2.3 §8.4
makes `FileChecksum` mandatory on a file entry and no rule could say so, because
there was nothing to point at.

Two absences matter here and they are not the same. A document with no file
inventory has broken nothing -- §8 makes the section optional and a
dependency-level SBOM legitimately has none. A file entry that exists and
carries no checksum has broken §8.4.
"""
import json

import pytest

from ossbomer.core import validators
from ossbomer.core.engine import _has_value, evaluate
from ossbomer.core.ir import File
from ossbomer.core.model import Category, Severity, Verdict
from ossbomer.core.parsers import parse_file
from ossbomer.core.profile import Profile, ProfileError, Rule, _parse_rule
from ossbomer.core.runner import run

SHA1 = "d6a770ba38583ed4bb4525bd96e50461655d2758"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

SPDX_FIXTURES = [
    "tests/fixtures/spdx/valid/spdx-2.3.json",
    "tests/fixtures/spdx/valid/spdx-2.3.spdx",
    "tests/fixtures/spdx/valid/spdx-2.3.xml",
    "tests/fixtures/spdx/valid/spdx-2.3.yaml",
]


def _spdx(tmp_path, files=None, name="files.spdx.json"):
    doc = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": "t",
        "documentNamespace": "https://example.com/t",
        "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: t-1.0"]},
        "packages": [{"SPDXID": "SPDXRef-P", "name": "p", "versionInfo": "1",
                      "downloadLocation": "NOASSERTION", "filesAnalyzed": False}],
    }
    if files is not None:
        doc["files"] = files
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return parse_file(str(path))


def _cdx(tmp_path, *components):
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z",
                     "tools": [{"name": "t", "version": "1"}]},
        "components": list(components),
    }
    path = tmp_path / "files.cdx.json"
    path.write_text(json.dumps(doc))
    return parse_file(str(path))


# ---- SPDX 2.x ----------------------------------------------------------------

@pytest.mark.parametrize("fixture", SPDX_FIXTURES)
def test_the_files_section_reaches_the_ir_in_every_encoding(fixture):
    """One parser feeds four encodings, so a per-encoding gap is possible and
    silent -- the tag-value reader is a different code path from the JSON one."""
    sbom = parse_file(fixture)
    assert sbom.files, f"{fixture} declares files that never reached the IR"
    assert all(f.hashes for f in sbom.files)


def test_a_file_entry_carries_its_id_name_and_checksums(tmp_path):
    sbom = _spdx(tmp_path, files=[{
        "SPDXID": "SPDXRef-F1", "fileName": "./src/a.c",
        "checksums": [{"algorithm": "SHA1", "checksumValue": SHA1}],
    }])
    (entry,) = sbom.files
    assert entry.spdx_id == "SPDXRef-F1"
    assert entry.name == "./src/a.c"
    assert entry.hashes == {"sha1": SHA1}


def test_a_document_with_no_files_section_has_an_empty_inventory(tmp_path):
    """Empty means the document declared none, not that it declared an empty
    one. Both formats make the section optional."""
    assert _spdx(tmp_path).files == []


def test_the_file_inventory_is_separate_from_the_component_list(tmp_path):
    """SPDX keeps files and packages in different sections, and a rule about
    file integrity must not sweep up packages."""
    sbom = _spdx(tmp_path, files=[{
        "SPDXID": "SPDXRef-F1", "fileName": "./src/a.c",
        "checksums": [{"algorithm": "SHA1", "checksumValue": SHA1}],
    }])
    assert len(sbom.components) == 1 and sbom.components[0].name == "p"
    assert len(sbom.files) == 1 and sbom.files[0].name == "./src/a.c"


# ---- CycloneDX ---------------------------------------------------------------

def test_a_file_typed_component_reaches_the_inventory(tmp_path):
    """CycloneDX has no files section: a file is a component of `type: file`."""
    sbom = _cdx(tmp_path,
                {"type": "file", "name": "src/a.c",
                 "hashes": [{"alg": "SHA-256", "content": SHA256}]})
    (entry,) = sbom.files
    assert entry.name == "src/a.c"
    assert entry.hashes == {"sha-256": SHA256}


def test_file_typed_components_stay_in_the_component_list_too(tmp_path):
    """Mirrored, not moved. Taking them out of `components` would change what
    every existing component rule sees on documents that have them, which is a
    verdict change this work has no reason to make.
    """
    sbom = _cdx(tmp_path,
                {"type": "library", "name": "lib", "version": "1.0"},
                {"type": "file", "name": "src/a.c"})
    assert [c.name for c in sbom.components] == ["lib", "src/a.c"]
    assert [f.name for f in sbom.files] == ["src/a.c"]


def _cdx_with_root(tmp_path, root, *components):
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": root},
        "components": list(components),
    }
    path = tmp_path / "root.cdx.json"
    path.write_text(json.dumps(doc))
    return parse_file(str(path))


def test_a_file_typed_root_component_counts_as_the_inventory(tmp_path):
    """A BOM describing a single file declares one, and saying "no file
    inventory" about it would be plainly wrong. SPDX has no equivalent blind
    spot: whatever its document describes already sits in `packages` or `files`.
    """
    sbom = _cdx_with_root(tmp_path, {
        "type": "file", "name": "app.bin",
        "hashes": [{"alg": "SHA-256", "content": SHA256}],
    })
    assert [f.name for f in sbom.files] == ["app.bin"]
    assert sbom.files[0].hashes == {"sha-256": SHA256}


def test_the_root_file_does_not_become_a_component(tmp_path):
    """`metadata.component` is the BOM's subject, not one of its parts, and this
    reader has always kept it out of `components`. Adding it to the inventory
    must not quietly change that -- every component rule would see a new entry.
    """
    sbom = _cdx_with_root(tmp_path, {"type": "file", "name": "app.bin"},
                          {"type": "file", "name": "src/a.c"})
    assert [c.name for c in sbom.components] == ["src/a.c"]
    assert [f.name for f in sbom.files] == ["app.bin", "src/a.c"]


def test_a_root_that_is_not_a_file_stays_out_of_the_inventory(tmp_path):
    sbom = _cdx_with_root(tmp_path, {"type": "application", "name": "app"},
                          {"type": "file", "name": "src/a.c"})
    assert [f.name for f in sbom.files] == ["src/a.c"]


def test_components_that_are_not_files_stay_out_of_the_inventory(tmp_path):
    sbom = _cdx(tmp_path, {"type": "library", "name": "lib", "version": "1.0"})
    assert sbom.files == []


def test_the_type_match_is_case_insensitive(tmp_path):
    sbom = _cdx(tmp_path, {"type": "File", "name": "src/a.c"})
    assert [f.name for f in sbom.files] == ["src/a.c"]


def test_a_file_component_with_no_hashes_is_kept_and_left_empty(tmp_path):
    """It must reach the inventory, or the rule that would fail it never runs.

    This case cannot come from SPDX: spdx-tools rejects a file entry with no
    checksum at parse time, enforcing §8.4 before any rule sees the document.
    CycloneDX has no such constraint, so this is where the rule earns its keep.
    """
    sbom = _cdx(tmp_path, {"type": "file", "name": "src/a.c"})
    (entry,) = sbom.files
    assert entry.hashes == {}


def test_nested_file_components_reach_the_inventory(tmp_path):
    """CycloneDX nests: a file belonging to a library is written inside that
    library's own `components`, which the spec's examples use freely.

    Reading only the top level meant a document declaring nested files *with*
    checksums reported "no file inventory in SBOM" -- an under-report on input
    no generator would consider unusual. This is the one defect on valid input
    that the malformed-input rounds never surfaced, because they were looking at
    a different class of problem.
    """
    sbom = _cdx(tmp_path, {
        "type": "library", "name": "lib", "version": "1.0",
        "components": [
            {"type": "file", "name": "lib/a.c",
             "hashes": [{"alg": "SHA-256", "content": SHA256}]},
            {"type": "library", "name": "inner", "components": [
                {"type": "file", "name": "deep/b.c"},
            ]},
        ],
    })
    assert [f.name for f in sbom.files] == ["lib/a.c", "deep/b.c"]


def test_nesting_does_not_change_the_component_list(tmp_path):
    """`components` stays top-level, as it has always been. Making it recurse
    would hand every existing component rule entries it has never judged -- a
    verdict change with no bearing on the file inventory."""
    sbom = _cdx(tmp_path, {
        "type": "library", "name": "lib",
        "components": [{"type": "file", "name": "lib/a.c"}],
    })
    assert [c.name for c in sbom.components] == ["lib"]


def test_the_described_subject_is_not_counted_twice(tmp_path):
    """A generator may name the root in `components` as well, and counting it
    twice would report the same file's checksum twice."""
    root = {"type": "file", "name": "app.bin", "bom-ref": "r1",
            "hashes": [{"alg": "SHA-256", "content": SHA256}]}
    sbom = _cdx_with_root(tmp_path, root, root)
    assert [f.name for f in sbom.files] == ["app.bin"]


def test_a_distinct_file_alongside_the_root_is_still_counted(tmp_path):
    """Dedup must not swallow a different file."""
    sbom = _cdx_with_root(tmp_path,
                          {"type": "file", "name": "app.bin", "bom-ref": "r1"},
                          {"type": "file", "name": "other.c", "bom-ref": "r2"})
    assert [f.name for f in sbom.files] == ["app.bin", "other.c"]


@pytest.mark.parametrize("bad_hash", [
    {"alg": None, "content": "x"},      # `alg` is required and a string
    {"alg": {"x": 1}, "content": "y"},
    {"alg": "SHA-256"},                 # no content
    "not-an-object",
    42,
])
def test_a_malformed_hash_entry_does_not_crash_the_parser(tmp_path, bad_hash):
    """A schema-invalid document must reach the schema gate, which is what
    reports it. Raising in the parser turns a reportable bad SBOM into an exit-2
    traceback, and the same comprehension had been written twice -- fixing one
    copy would have left the other crashing.
    """
    sbom = _cdx(tmp_path,
                {"type": "file", "name": "src/a.c", "hashes": [bad_hash]},
                {"type": "library", "name": "lib", "hashes": [bad_hash]})
    assert sbom.files[0].hashes == {}
    assert sbom.components[1].hashes == {}


def test_a_good_hash_survives_alongside_a_malformed_one(tmp_path):
    """Tolerating junk must not mean discarding what was valid."""
    sbom = _cdx(tmp_path, {"type": "file", "name": "src/a.c", "hashes": [
        {"alg": None, "content": "x"},
        {"alg": "SHA-256", "content": SHA256},
    ]})
    assert sbom.files[0].hashes == {"sha-256": SHA256}


# ---- SPDX 3.0 ----------------------------------------------------------------

def _spdx3(tmp_path, *nodes):
    doc = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"type": "CreationInfo", "spdxId": "_:ci", "specVersion": "3.0.1",
             "created": "2026-01-01T00:00:00Z", "createdBy": ["_:agent"]},
            {"type": "SpdxDocument", "spdxId": "https://example.com/d",
             "creationInfo": "_:ci", "name": "d"},
            *nodes,
        ],
    }
    path = tmp_path / "d.spdx.jsonld"
    path.write_text(json.dumps(doc))
    return parse_file(str(path))


def test_spdx3_software_file_nodes_reach_the_inventory(tmp_path):
    """3.0 replaced 2.x's `checksums` with `verifiedUsing` integrity methods."""
    sbom = _spdx3(tmp_path, {
        "type": "software_File", "spdxId": "https://example.com/f/a",
        "creationInfo": "_:ci", "name": "src/a.c",
        "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": SHA256}],
    })
    (entry,) = sbom.files
    assert entry.name == "src/a.c"
    assert entry.hashes == {"sha256": SHA256}


def test_spdx3_namespaced_hash_algorithms_are_trimmed(tmp_path):
    """The algorithm arrives bare or namespaced depending on the writer."""
    sbom = _spdx3(tmp_path, {
        "type": "software_File", "spdxId": "https://example.com/f/a",
        "creationInfo": "_:ci", "name": "src/a.c",
        "verifiedUsing": [{"type": "Hash", "algorithm": "hashAlgorithm_sha256",
                           "hashValue": SHA256}],
    })
    assert sbom.files[0].hashes == {"sha256": SHA256}


def test_spdx3_integrity_methods_that_are_not_hashes_are_ignored(tmp_path):
    sbom = _spdx3(tmp_path, {
        "type": "software_File", "spdxId": "https://example.com/f/a",
        "creationInfo": "_:ci", "name": "src/a.c",
        "verifiedUsing": [{"type": "PackageVerificationCode", "hashValue": SHA256}],
    })
    assert sbom.files[0].hashes == {}


def test_spdx3_packages_stay_out_of_the_inventory(tmp_path):
    sbom = _spdx3(tmp_path, {
        "type": "software_Package", "spdxId": "https://example.com/p",
        "creationInfo": "_:ci", "name": "p", "software_packageVersion": "1.0",
    })
    assert sbom.files == []
    assert [c.name for c in sbom.components] == ["p"]


def test_expanded_jsonld_parses_the_same_as_the_compact_form(tmp_path):
    """JSON-LD carries one graph in more than one shape.

    Compacted against the SPDX context a node reads `"type": "software_File"`
    and `"spdxId"`; expanded, it reads `"@type"` with a full IRI and `"@id"`.
    Only the first was matched, so an expanded document parsed to nothing at all
    -- no components, no files, no creation info -- and was reported as an SBOM
    that declared nothing rather than one that could not be read. That predates
    the file inventory and applied to packages and the document node too.
    """
    terms = "https://spdx.org/rdf/3.0.1/terms"
    expanded = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"@type": f"{terms}/Core/CreationInfo", "@id": "_:ci",
             "specVersion": "3.0.1", "created": "2026-01-01T00:00:00Z",
             "createdBy": ["_:agent"]},
            {"@type": f"{terms}/Core/SpdxDocument", "@id": "https://example.com/d",
             "name": "d"},
            # A list of types, which expanded JSON-LD permits.
            {"@type": [f"{terms}/Software/Package"], "@id": "https://example.com/p",
             "name": "p", "software_packageVersion": "1.0"},
            {"@type": f"{terms}/Software/File", "@id": "https://example.com/f",
             "name": "src/a.c",
             "verifiedUsing": [{"@type": f"{terms}/Core/Hash",
                                "algorithm": "sha256", "hashValue": SHA256}]},
        ],
    }
    path = tmp_path / "expanded.spdx.jsonld"
    path.write_text(json.dumps(expanded))
    sbom = parse_file(str(path))

    assert sbom.document.timestamp == "2026-01-01T00:00:00Z"
    assert [c.name for c in sbom.components] == ["p", "src/a.c"]
    assert [f.name for f in sbom.files] == ["src/a.c"]
    assert sbom.files[0].spdx_id == "https://example.com/f"
    assert sbom.files[0].hashes == {"sha256": SHA256}


@pytest.mark.parametrize("algorithm,expected", [
    ("sha256", "sha256"),
    ("hashAlgorithm_sha256", "sha256"),
    ("sha3_256", "sha3_256"),
    ("hashAlgorithm_sha3_256", "sha3_256"),
    ("blake2b256", "blake2b256"),
    ("https://spdx.org/rdf/3.0.1/terms/Core/HashAlgorithm/sha3_512", "sha3_512"),
])
def test_only_the_hash_algorithm_prefix_is_trimmed(tmp_path, algorithm, expected):
    """`sha3_256` has an underscore inside the name.

    Splitting on every underscore left `256`, which is a different algorithm and
    one `hash_algorithm_in_set` would not recognise -- so a file with a valid
    SHA3-256 digest would fail a rule that allows SHA3-256.
    """
    sbom = _spdx3(tmp_path, {
        "type": "software_File", "spdxId": "https://example.com/f",
        "creationInfo": "_:ci", "name": "src/a.c",
        "verifiedUsing": [{"type": "Hash", "algorithm": algorithm, "hashValue": SHA256}],
    })
    assert list(sbom.files[0].hashes) == [expected]


def test_an_expanded_document_also_passes_the_schema_gate(tmp_path):
    """Reading a shape the gate then rejects is not support.

    `validate_schema` built its type set from `"type"` alone, so an expanded
    document parsed into the IR correctly and was still reported schema-invalid
    -- "@graph contains no SpdxDocument/CreationInfo element" for a graph that
    plainly had both. Parser and gate share one normaliser now.
    """
    terms = "https://spdx.org/rdf/3.0.1/terms"
    doc = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"@type": f"{terms}/Core/CreationInfo", "@id": "_:ci",
             "specVersion": "3.0.1", "created": "2026-01-01T00:00:00Z",
             "createdBy": ["_:agent"]},
            {"@type": f"{terms}/Core/SpdxDocument", "@id": "https://example.com/d",
             "name": "d"},
        ],
    }
    path = tmp_path / "expanded.spdx.jsonld"
    path.write_text(json.dumps(doc))
    (result,) = run(str(path), ["cisa-2026-min"])
    schema = [f for f in result.findings if f.rule_id == "schema-valid"]
    assert [f.verdict for f in schema] == [Verdict.PASS]


@pytest.mark.parametrize("bad_type", [1, None, {"a": 1}, ["file"]])
def test_a_non_string_component_type_does_not_crash_the_parser(tmp_path, bad_type):
    """A schema-invalid document must still reach the schema gate.

    Selecting file components on `type` introduced a `.lower()` on whatever the
    document put there. Crashing in the parser replaces a clear schema failure
    with a traceback, and the hostile-input path exists precisely so that does
    not happen.
    """
    sbom = _cdx(tmp_path, {"type": bad_type, "name": "x"},
                {"type": "file", "name": "src/a.c"})
    assert [f.name for f in sbom.files] == ["src/a.c"]


def test_a_type_list_is_read_in_full(tmp_path):
    """`@type` may carry a node's whole ancestry, and the first entry is not the
    authoritative one. Reading only `raw[0]` turned
    `["…/Core/Element", "…/Software/File"]` into `Element`, so a good file node
    was skipped and the schema gate then called the document incomplete.
    """
    terms = "https://spdx.org/rdf/3.0.1/terms"
    doc = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"@type": [f"{terms}/Core/Element", f"{terms}/Core/CreationInfo"],
             "@id": "_:ci", "specVersion": "3.0.1",
             "created": "2026-01-01T00:00:00Z", "createdBy": ["_:agent"]},
            {"@type": [f"{terms}/Core/Element", f"{terms}/Core/SpdxDocument"],
             "@id": "https://example.com/d", "name": "d"},
            {"@type": [f"{terms}/Core/Element", f"{terms}/Software/File"],
             "@id": "https://example.com/f", "name": "src/a.c",
             "verifiedUsing": [{"@type": [f"{terms}/Core/Hash"],
                                "algorithm": "sha256", "hashValue": SHA256}]},
        ],
    }
    path = tmp_path / "multitype.spdx.jsonld"
    path.write_text(json.dumps(doc))
    sbom = parse_file(str(path))
    assert [f.name for f in sbom.files] == ["src/a.c"]
    assert sbom.files[0].hashes == {"sha256": SHA256}
    assert sbom.document.timestamp == "2026-01-01T00:00:00Z"

    (result,) = run(str(path), ["cisa-2026-min"])
    assert [f.verdict for f in result.findings if f.rule_id == "schema-valid"] == [Verdict.PASS]


@pytest.mark.parametrize("key", ["software_copyrightText", "copyrightText"])
def test_spdx3_file_copyright_reaches_the_ir(tmp_path, key):
    """A direct property in 3.0, and filled on the other two paths, so leaving
    it empty would make the same file answer differently by format.

    Both spellings, because the JSON-LD context qualifies a profile's properties
    and writers differ on whether the prefix survives compaction. The version
    lookup has accepted both since it was written.
    """
    sbom = _spdx3(tmp_path, {
        "type": "software_File", "spdxId": "https://example.com/f",
        "creationInfo": "_:ci", "name": "src/a.c",
        key: "Copyright 2026 Example",
    })
    assert sbom.files[0].copyright == "Copyright 2026 Example"


@pytest.mark.parametrize("key", ["software_packageVersion", "packageVersion"])
def test_spdx3_package_version_accepts_both_spellings(tmp_path, key):
    """The precedent this generalises. Pinned so folding it into the shared
    lookup cannot quietly drop one of the two spellings it already handled."""
    sbom = _spdx3(tmp_path, {
        "type": "software_Package", "spdxId": "https://example.com/p",
        "creationInfo": "_:ci", "name": "p", key: "1.0",
    })
    assert sbom.components[0].version == "1.0"


def test_spdx3_file_licenses_are_a_known_gap(tmp_path):
    """Recorded rather than assumed.

    Licensing in 3.0 is a relationship to a separate license element, not a
    property on the file, so a field lookup cannot find it. Components are in
    exactly the same position, so this is not something the file inventory
    regressed -- and resolving it for files alone would be the half-fix this
    branch has already had to undo once.
    """
    sbom = _spdx3(tmp_path, {
        "type": "software_File", "spdxId": "https://example.com/f",
        "creationInfo": "_:ci", "name": "src/a.c",
    })
    assert sbom.files[0].licenses == []


def test_a_single_verified_using_hash_may_arrive_unwrapped(tmp_path):
    """JSON-LD compaction collapses a one-element array to a bare object unless
    the context pins `@container: @set`, so one hash arrives either way.
    Iterating the bare object walked its keys, found no dicts, and left the file
    looking unchecksummed when it carried one."""
    sbom = _spdx3(tmp_path, {
        "type": "software_File", "spdxId": "https://example.com/f",
        "creationInfo": "_:ci", "name": "src/a.c",
        "verifiedUsing": {"type": "Hash", "algorithm": "sha256", "hashValue": SHA256},
    })
    assert sbom.files[0].hashes == {"sha256": SHA256}


@pytest.mark.parametrize("declared,allowed,expected", [
    ("sha3_256", "SHA3-256", True),     # SPDX 3.0's spelling
    ("sha3-256", "SHA3-256", True),     # CycloneDX's
    ("SHA3256", "SHA3-256", True),
    ("sha256", "SHA3-256", False),      # a different algorithm, still rejected
])
def test_algorithm_names_compare_across_separators(declared, allowed, expected):
    """Every source spells the separator differently. Stripping only the hyphen
    left the underscore form comparing unequal, so a valid SHA3-256 digest from
    an SPDX 3.0 document failed a rule that allows SHA3-256.
    """
    ok, _ = validators.get("hash_algorithm_in_set")(
        {declared: "ab" * 32}, validators.ValidatorContext(None), {"algs": [allowed]})
    assert ok is expected


def test_fully_expanded_jsonld_is_still_out_of_scope(tmp_path):
    """Recorded so the limit is known rather than assumed.

    The fully expanded form -- a top-level array, properties keyed by IRI,
    values boxed in `@value` -- is rejected at detection, before any of the type
    normalisation above runs. Accepting `@type`/`@id` did not change that, and
    claiming otherwise would overstate what this reads.
    """
    from ossbomer.core.detect import DetectionError

    terms = "https://spdx.org/rdf/3.0.1/terms"
    path = tmp_path / "expanded.jsonld"
    path.write_text(json.dumps([
        {"@id": "_:ci", "@type": [f"{terms}/Core/CreationInfo"],
         f"{terms}/Core/created": [{"@value": "2026-01-01T00:00:00Z"}]},
    ]))
    with pytest.raises(DetectionError):
        parse_file(str(path))


# ---- identity ----------------------------------------------------------------

@pytest.mark.parametrize("entry,expected", [
    (File(name="src/a.c", spdx_id="SPDXRef-F1"), "src/a.c"),
    (File(spdx_id="SPDXRef-F1"), "SPDXRef-F1"),
    (File(), "<unknown>"),
])
def test_file_identity_prefers_the_path(entry, expected):
    assert entry.identity == expected


# ---- the file rule scope -----------------------------------------------------

def _profile(severity):
    return Profile(id="t", name="t", rules=[Rule(
        id="file-has-checksum", scope="file", severity=severity,
        category=Category.COMPLETENESS, field="hashes",
        citation="SPDX 2.3 §8.4", validators=["present", "hash_wellformed"],
    )])


def _verdicts(sbom, severity):
    return [(f.path, f.verdict) for f in evaluate(sbom, _profile(severity))]


def test_a_file_with_a_good_checksum_passes(tmp_path):
    sbom = _cdx(tmp_path, {"type": "file", "name": "src/a.c",
                           "hashes": [{"alg": "SHA-256", "content": SHA256}]})
    assert _verdicts(sbom, Severity.MUST) == [("files[0]:src/a.c", Verdict.PASS)]


@pytest.mark.parametrize("severity,expected", [
    (Severity.MUST, Verdict.FAIL),
    (Severity.MUST_WHERE_AVAILABLE, Verdict.WARN),
])
def test_within_an_entry_the_severity_governs(tmp_path, severity, expected):
    """A file entry that exists and has no checksum has broken §8.4, so a `MUST`
    rule fails it. This is the half that must keep biting."""
    sbom = _cdx(tmp_path, {"type": "file", "name": "src/a.c"})
    assert _verdicts(sbom, severity) == [("files[0]:src/a.c", expected)]


@pytest.mark.parametrize("severity", list(Severity))
def test_no_file_inventory_is_never_a_violation(tmp_path, severity):
    """The criterion this scope exists to satisfy.

    Deriving this from the severity would make a `MUST` file rule fail every
    SBOM that simply does not enumerate files -- the requirement inverted. The
    section is optional in both formats, so its absence is reported the same way
    an SBOM with no components is, whatever the rule says.
    """
    sbom = _cdx(tmp_path, {"type": "library", "name": "lib", "version": "1.0"})
    assert _verdicts(sbom, severity) == [("files", Verdict.WARN)]


def test_absence_is_reported_rather_than_passed_over(tmp_path):
    """Silence would make "nothing was checked" look like "checked and fine"."""
    sbom = _cdx(tmp_path, {"type": "library", "name": "lib", "version": "1.0"})
    (finding,) = evaluate(sbom, _profile(Severity.MUST))
    assert finding.message == "no file inventory in SBOM"


def test_every_file_is_evaluated_not_just_the_first(tmp_path):
    sbom = _cdx(tmp_path,
                {"type": "file", "name": "a.c",
                 "hashes": [{"alg": "SHA-256", "content": SHA256}]},
                {"type": "file", "name": "b.c"})
    assert _verdicts(sbom, Severity.MUST) == [
        ("files[0]:a.c", Verdict.PASS),
        ("files[1]:b.c", Verdict.FAIL),
    ]


# ---- `present` over a mapping ------------------------------------------------
# Found while writing the rule above: `field: hashes` with `present` passed a
# component or file carrying no hashes at all. `_as_list` had no branch for a
# mapping, so `{}` fell through to the catch-all and came back as `[{}]` --
# non-empty, therefore present. No bundled profile paired `present` with a
# mapping field, so nothing shipped was wrong; the natural spelling of a file
# checksum rule is the first thing that needed it.

@pytest.mark.parametrize("value,expected", [
    ({}, False),
    ({"sha256": SHA256}, True),
    ({"sha256": ""}, False),
    ({"sha256": "NOASSERTION"}, False),
    ({"a": "", "b": SHA256}, True),
    ([], False),
    (["x"], True),
    (None, False),
    ("", False),
])
def test_present_reads_a_mapping_by_its_values(value, expected):
    ok, _ = validators.get("present")(value, validators.ValidatorContext(None), {})
    assert ok is expected


@pytest.mark.parametrize("value", [
    {}, {"sha256": SHA256}, {"sha256": ""}, {"sha256": "NOASSERTION"},
    {"a": "", "b": SHA256}, [], [""], ["x"], None, "", "x",
])
def test_present_and_has_value_agree(value):
    """They answer the same question in two places -- `present` for the rule,
    `_has_value` for MUST_WHERE_AVAILABLE and multi-field lookup. Drift between
    them means a rule reports absence while the severity says data was there.
    """
    ok, _ = validators.get("present")(value, validators.ValidatorContext(None), {})
    assert ok is _has_value(value)


# ---- scope validation --------------------------------------------------------
# A rule naming a scope the engine does not handle produced no findings at all,
# which reads as a clean pass. `file` and `files` are one keystroke apart.

def _raw(scope):
    return {"id": "r", "scope": scope, "severity": "MUST",
            "category": "Completeness", "citation": "c", "validators": ["present"]}


@pytest.mark.parametrize("scope", ["document", "component", "file", "dependency"])
def test_known_scopes_parse(scope):
    assert _parse_rule(_raw(scope)).scope == scope


@pytest.mark.parametrize("scope", ["files", "Component", "packages", ""])
def test_an_unknown_scope_is_refused_rather_than_ignored(scope):
    with pytest.raises(ProfileError, match="unknown scope"):
        _parse_rule(_raw(scope))


def test_scope_defaults_to_document():
    raw = _raw("document")
    del raw["scope"]
    assert _parse_rule(raw).scope == "document"
