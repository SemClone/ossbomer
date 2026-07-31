"""Backward-compatible SBOMSchemaValidator API (N4).

These exercise the legacy method names against the known-good multi-version
fixture corpus. The exhaustive version matrix lives in test_version_matrix.py.
"""
import os
import unittest

from ossbomer.schema.validator import SBOMSchemaValidator

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")


class TestLegacySchemaAPI(unittest.TestCase):
    def setUp(self):
        self.validator = SBOMSchemaValidator()

    def test_valid_cyclonedx_json(self):
        result = self.validator.validate_cyclonedx_json(
            os.path.join(FIX, "cyclonedx", "valid", "cdx-1.4.json"))
        self.assertEqual(result, "Valid")

    def test_valid_cyclonedx_xml(self):
        result = self.validator.validate_cyclonedx_xml(
            os.path.join(FIX, "cyclonedx", "valid", "cdx-1.4.xml"))
        self.assertEqual(result, "Valid")

    def test_valid_spdx_json(self):
        result = self.validator.validate_spdx_json(
            os.path.join(FIX, "spdx", "valid", "spdx-2.3.json"))
        self.assertEqual(result, "Valid")

    def test_valid_spdx_xml(self):
        # The only method of the four that had no coverage, which is how a
        # malformed SPDX XML fixture went unnoticed for so long.
        result = self.validator.validate_spdx_xml(
            os.path.join(FIX, "spdx", "valid", "spdx-2.3.xml"))
        self.assertEqual(result, "Valid")

    def test_invalid_cyclonedx_json(self):
        result = self.validator.validate_cyclonedx_json(
            os.path.join(FIX, "cyclonedx", "invalid", "cdx-1.4-badtype.json"))
        self.assertNotEqual(result, "Valid")

    def test_new_structured_api_autodetects(self):
        result = self.validator.validate(
            os.path.join(FIX, "cyclonedx", "valid", "cdx-1.6.json"))
        self.assertTrue(result.valid)
        self.assertEqual(result.spec_version, "1.6")


if __name__ == "__main__":
    unittest.main()
