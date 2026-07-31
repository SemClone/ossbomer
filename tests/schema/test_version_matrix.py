"""Multi-version schema validation matrix.

Regression coverage for the two original bugs:
  1. CycloneDX JSON was always validated against the 1.4 schema.
  2. XML validation was stubbed to always return "Valid".
Now every fixture is validated against its *detected* version.
"""
import glob
import os

import pytest

from ossbomer.core.detect import detect_file
from ossbomer.core.schema_validation import validate_schema

HERE = os.path.dirname(__file__)
FIX = os.path.join(HERE, "..", "fixtures")


def _fixtures(subpath):
    return sorted(glob.glob(os.path.join(FIX, subpath)))


VALID = _fixtures("cyclonedx/valid/*") + _fixtures("spdx/valid/*")
INVALID = _fixtures("cyclonedx/invalid/*") + _fixtures("spdx/invalid/*")

# (path, expected_format, expected_version_prefix, expected_encoding)
EXPECTED = {
    "cdx-1.3.json": ("cyclonedx", "1.3", "json"),
    "cdx-1.4.json": ("cyclonedx", "1.4", "json"),
    "cdx-1.5.json": ("cyclonedx", "1.5", "json"),
    "cdx-1.6.json": ("cyclonedx", "1.6", "json"),
    "cdx-1.3.xml": ("cyclonedx", "1.3", "xml"),
    "cdx-1.4.xml": ("cyclonedx", "1.4", "xml"),
    "cdx-1.5.xml": ("cyclonedx", "1.5", "xml"),
    "cdx-1.6.xml": ("cyclonedx", "1.6", "xml"),
    "spdx-2.2.json": ("spdx", "2.2", "json"),
    "spdx-2.3.json": ("spdx", "2.3", "json"),
    "spdx-2.2.spdx": ("spdx", "2.2", "tagvalue"),
    "spdx-2.3.spdx": ("spdx", "2.3", "tagvalue"),
    "spdx-2.2.yaml": ("spdx", "2.2", "yaml"),
    "spdx-2.3.yaml": ("spdx", "2.3", "yaml"),
    "spdx-2.3.xml": ("spdx", "2.3", "xml"),
    "spdx-2.3.rdf.xml": ("spdx", "2.3", "xml"),
    "spdx-3.0.jsonld": ("spdx", "3.0", "json"),
}

# Every serialization SPDX defines, so a format gaining coverage is a deliberate
# fixture addition rather than a silent gap. `spdx-tools` dispatches on the file
# extension, which is why each encoding needs its own file to be exercised at all.
SPDX_ENCODINGS_COVERED = {"json", "tagvalue", "yaml", "xml"}


def test_fixtures_exist():
    assert VALID, "no valid fixtures found"
    assert INVALID, "no invalid fixtures found"


@pytest.mark.parametrize("path", VALID, ids=lambda p: os.path.basename(p))
def test_valid_fixtures_validate(path):
    result = validate_schema(path)
    assert result.valid, f"{path} should be VALID but got: {result.errors}"


@pytest.mark.parametrize("path", INVALID, ids=lambda p: os.path.basename(p))
def test_invalid_fixtures_rejected(path):
    result = validate_schema(path)
    assert not result.valid, f"{path} should be INVALID but validated clean"


@pytest.mark.parametrize("path", VALID, ids=lambda p: os.path.basename(p))
def test_detection_picks_correct_version(path):
    name = os.path.basename(path)
    if name not in EXPECTED:
        pytest.skip(f"no expectation registered for {name}")
    exp_format, exp_ver, exp_enc = EXPECTED[name]
    det = detect_file(path)
    assert det.sbom_format == exp_format
    assert det.spec_version.startswith(exp_ver)
    assert det.encoding == exp_enc


def test_every_spdx_encoding_has_a_fixture():
    """Each SPDX serialization must be represented, or it is untested by accident.

    SPDX XML in particular sat unexercised behind a fixture whose root tag was
    `SpdxDocument` instead of `Document`, so it never parsed and nothing noticed.
    """
    encodings = {
        detect_file(p).encoding
        for p in _fixtures("spdx/valid/*")
    }
    missing = SPDX_ENCODINGS_COVERED - encodings
    assert not missing, f"no valid SPDX fixture for encoding(s): {sorted(missing)}"


def test_spdx_yaml_is_not_mistaken_for_tagvalue():
    """SPDX YAML and tag-value both spell `SPDXID:`, so YAML needs its own branch."""
    p = os.path.join(FIX, "spdx", "valid", "spdx-2.3.yaml")
    det = detect_file(p)
    assert det.encoding == "yaml", f"YAML detected as {det.encoding!r}"
    assert det.spec_version.startswith("2.3")


def test_empty_document_is_not_reported_as_broken_json():
    """`"" in "{["` is True, so an empty file must be special-cased."""
    import tempfile

    from ossbomer.core.detect import DetectionError
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        tmp = fh.name
    try:
        with pytest.raises(DetectionError, match="empty"):
            detect_file(tmp)
    finally:
        os.unlink(tmp)


def test_cyclonedx_version_not_hardcoded_to_1_4():
    """A 1.6 document must be detected and validated as 1.6, not silently as 1.4."""
    p = os.path.join(FIX, "cyclonedx", "valid", "cdx-1.6.json")
    result = validate_schema(p)
    assert result.spec_version == "1.6"
    assert result.valid


def test_xml_is_really_validated():
    """XML validation must be real: a malformed CycloneDX XML must fail."""
    import tempfile
    bad_xml = '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.4">' \
              '<components><component type="not-a-type"></component></components></bom>'
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as fh:
        fh.write(bad_xml)
        tmp = fh.name
    try:
        result = validate_schema(tmp)
        assert not result.valid, "XML validation regression: malformed XML passed"
    finally:
        os.unlink(tmp)
