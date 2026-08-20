"""A malformed document must survive to the schema gate, not raise on the way.

The schema promises a shape; the document is not obliged to keep that promise.
This parser is not what reports the breach -- `validate_schema` is, and it only
runs if parsing survives to call it. Raising on a malformed field replaced a
usable "your SBOM is invalid because X" with a traceback and exit 2, on
precisely the input a validator exists to be handed.

Seven sites crashed before this: `metadata`, `components` and `dependencies` at
the top level, and `properties`, `licenses`, `hashes` and nested `components`
within a component. Three more had already been fixed one at a time as
adversarial review happened to reach them.

That history is why this file is generative rather than a list of cases. Fixing
by enumeration looks finished long before it is: the failures are not uniform
per field, since `licenses: 42` crashes where `licenses: {}` does not, different
call sites reaching different operations on the same bad value. A list of the
inputs someone thought of is a list of the inputs someone thought of.
"""
import copy
import itertools
import json

import pytest

from ossbomer.core.detect import DetectionError
from ossbomer.core.parsers import parse_file
from ossbomer.core.runner import run
from ossbomer.core.schema_validation import validate_schema

# Values a JSON document can legally hold and a CycloneDX document may not, at
# any given field. Every one has crashed the mapper somewhere.
JUNK = [42, None, "a string", [], {}, [42], ["a string"], {"unexpected": 1}, True, 1.5]

# A valid 1.6 document with every container this mapper reads actually populated.
# Mutating a document whose fields are absent proves nothing: the crash needs
# something of the wrong type to be *there*.
VALID = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:509b1666-c1f2-4b3e-abd4-80bf52aa5ece",
    "version": 1,
    "metadata": {
        "timestamp": "2026-01-01T00:00:00Z",
        "lifecycles": [{"phase": "build"}],
        "tools": {"components": [{"type": "application", "name": "gen", "version": "1.0"}]},
        "authors": [{"name": "Ada Lovelace", "email": "ada@example.org"}],
        "supplier": {"name": "Example Corp"},
        "manufacturer": {"name": "Example Corp"},
        "component": {
            "type": "application", "name": "app", "version": "1.0",
            "bom-ref": "app@1.0",
            "components": [{"type": "file", "name": "app/main.c",
                            "hashes": [{"alg": "SHA-256", "content": "a" * 64}]}],
        },
    },
    "components": [
        {
            "type": "library", "name": "lib", "version": "2.0",
            "bom-ref": "lib@2.0", "purl": "pkg:npm/lib@2.0",
            "cpe": "cpe:2.3:a:vendor:lib:2.0:*:*:*:*:*:*:*",
            "supplier": {"name": "Lib Author"},
            "author": "Lib Author", "publisher": "Lib Author",
            "copyright": "Copyright 2026",
            "licenses": [{"license": {"id": "MIT"}}],
            "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
            "externalReferences": [{"type": "website", "url": "https://example.org"}],
            "properties": [{"name": "k", "value": "v"}],
            "components": [{"type": "file", "name": "lib/a.c",
                            "hashes": [{"alg": "SHA-256", "content": "c" * 64}]}],
        },
    ],
    "dependencies": [{"ref": "app@1.0", "dependsOn": ["lib@2.0"]}],
}

# Every field the mapper reads, as a path into the document above.
PATHS = [
    ("metadata",),
    ("metadata", "timestamp"),
    ("metadata", "lifecycles"),
    ("metadata", "tools"),
    ("metadata", "tools", "components"),
    ("metadata", "authors"),
    ("metadata", "supplier"),
    ("metadata", "manufacturer"),
    ("metadata", "component"),
    ("metadata", "component", "components"),
    ("components",),
    ("components", 0),
    ("components", 0, "type"),
    ("components", 0, "name"),
    ("components", 0, "version"),
    ("components", 0, "bom-ref"),
    ("components", 0, "purl"),
    ("components", 0, "cpe"),
    ("components", 0, "supplier"),
    ("components", 0, "author"),
    ("components", 0, "copyright"),
    ("components", 0, "licenses"),
    ("components", 0, "hashes"),
    ("components", 0, "externalReferences"),
    ("components", 0, "properties"),
    ("components", 0, "components"),
    ("dependencies",),
    ("dependencies", 0),
    ("dependencies", 0, "ref"),
    ("dependencies", 0, "dependsOn"),
]


def _mutate(path, value):
    doc = copy.deepcopy(VALID)
    target = doc
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    return doc


def _write(tmp_path, doc, name="m.cdx.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


def test_the_baseline_document_is_actually_valid(tmp_path):
    """Without this the whole file could pass by mutating something already
    broken, and prove nothing about anything."""
    result = validate_schema(_write(tmp_path, VALID))
    assert result.valid, result.errors


@pytest.mark.parametrize("path,value", list(itertools.product(PATHS, JUNK)),
                         ids=lambda x: ".".join(map(str, x)) if isinstance(x, tuple) else repr(x))
def test_parsing_survives_any_junk_at_any_field(tmp_path, path, value):
    """300 documents: every field the mapper reads, against ten wrong types.

    The assertion is only that `parse_file` returns. What it returns for a
    malformed field is the schema gate's business, not this test's -- pinning
    that would be pinning the implementation.
    """
    sbom = parse_file(_write(tmp_path, _mutate(path, value)))
    assert sbom.sbom_format == "cyclonedx"


@pytest.mark.parametrize("path", PATHS, ids=lambda p: ".".join(map(str, p)))
def test_a_run_completes_and_reports_rather_than_raising(tmp_path, path):
    """End to end, since surviving `parse_file` is not the point on its own --
    reaching a verdict the user can read is."""
    for value in JUNK:
        (result,) = run(_write(tmp_path, _mutate(path, value)), ["cisa-2026-min"])
        assert result.verdict.value in {"PASS", "WARN", "FAIL"}


def test_valid_data_beside_malformed_data_is_kept(tmp_path):
    """Surviving junk must not mean discarding the document.

    A mapper that answered every malformed field by returning nothing at all
    would pass every test above while destroying the parts the document got
    right.
    """
    doc = _mutate(("components", 0, "properties"), 42)
    sbom = parse_file(_write(tmp_path, doc))
    (component,) = sbom.components
    assert component.name == "lib"
    assert component.version == "2.0"
    assert component.purl == "pkg:npm/lib@2.0"
    assert component.licenses == ["MIT"]
    assert component.hashes == {"sha-256": "b" * 64}
    assert component.properties == {}


def test_a_malformed_document_still_fails_schema_validation(tmp_path):
    """The point of surviving. A junk field must be reported, not swallowed."""
    path = _write(tmp_path, _mutate(("components",), 42))
    assert not validate_schema(path).valid

    (result,) = run(path, ["cisa-2026-min"])
    schema = [f for f in result.findings if f.rule_id == "schema-valid"]
    assert [f.verdict.value for f in schema] == ["FAIL"]


# ---- SPDX 3.0 ----------------------------------------------------------------
# The 3.0 reader is hand-rolled like the CycloneDX one and owes the same
# contract. It is best-effort about *shapes* it understands; that is not licence
# to raise on shapes it does not.

SPDX3_VALID = {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
        {"type": "CreationInfo", "spdxId": "_:ci", "specVersion": "3.0.1",
         "created": "2026-01-01T00:00:00Z", "createdBy": ["_:agent"]},
        {"type": "SpdxDocument", "spdxId": "https://example.com/d", "name": "d"},
        {"type": "software_Package", "spdxId": "https://example.com/p", "name": "p",
         "software_packageVersion": "1.0"},
        {"type": "software_File", "spdxId": "https://example.com/f", "name": "a.c",
         "verifiedUsing": [{"type": "Hash", "algorithm": "sha256",
                            "hashValue": "a" * 64}]},
    ],
}

SPDX3_PATHS = [
    ("@graph",),
    ("@graph", 0),
    ("@graph", 0, "type"),
    ("@graph", 0, "spdxId"),
    ("@graph", 0, "created"),
    ("@graph", 0, "createdBy"),
    ("@graph", 2, "name"),
    ("@graph", 2, "software_packageVersion"),
    ("@graph", 3, "name"),
    ("@graph", 3, "verifiedUsing"),
    ("@graph", 3, "verifiedUsing", 0),
    ("@graph", 3, "verifiedUsing", 0, "algorithm"),
    ("@graph", 3, "verifiedUsing", 0, "hashValue"),
]


def _spdx3_mutate(path, value):
    doc = copy.deepcopy(SPDX3_VALID)
    target = doc
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    return doc


@pytest.mark.parametrize("path,value", list(itertools.product(SPDX3_PATHS, JUNK)),
                         ids=lambda x: ".".join(map(str, x)) if isinstance(x, tuple) else repr(x))
def test_spdx3_parsing_survives_any_junk_at_any_field(tmp_path, path, value):
    doc = _spdx3_mutate(path, value)
    path_str = _write(tmp_path, doc, name="m.spdx.jsonld")
    try:
        sbom = parse_file(path_str)
    except DetectionError:
        # Mutating the marker detection keys on can make the document
        # unrecognisable, which is a refusal rather than a crash.
        return
    assert sbom.sbom_format == "spdx"


def test_a_document_that_is_not_an_object_does_not_crash(tmp_path):
    """The outermost container gets the same treatment as the inner ones."""
    for doc in ([], [VALID], "a string", 42):
        p = tmp_path / "top.cdx.json"
        # Keep the CycloneDX marker so detection still routes it here rather
        # than rejecting it before the mapper is reached.
        p.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                 "version": 1, "components": doc}))
        assert parse_file(str(p)).sbom_format == "cyclonedx"
