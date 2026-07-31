"""SBOM schema validation (SPDX + CycloneDX), version-aware.

Thin compatibility layer over :mod:`ossbomer.core.schema_validation`. The legacy
method names from the standalone ``ossbomer-schema`` package are preserved (N4),
but they now detect and validate against the document's *actual* declared version
instead of a hardcoded one.
"""
from __future__ import annotations

from ossbomer.core.schema_validation import SchemaResult, validate_schema


class SBOMSchemaValidator:
    """Backward-compatible validator.

    New code should prefer :func:`ossbomer.core.schema_validation.validate_schema`,
    which returns a structured :class:`SchemaResult` and auto-detects the format.
    """

    def validate(self, file_path: str) -> SchemaResult:
        """Auto-detect format/version and validate. Returns a structured result."""
        return validate_schema(file_path)

    # --- legacy string-returning API ("Valid" or an error message) ------------

    def _forced(self, file_path: str, sbom_format: str, encoding: str) -> str:
        # Preserve the old signatures but route through the version-aware core.
        # We still auto-detect the version; only the format/encoding are asserted.
        result = validate_schema(file_path)
        if result.sbom_format != sbom_format or result.encoding != encoding:
            return (f"Format mismatch: detected {result.sbom_format} ({result.encoding}), "
                    f"expected {sbom_format} ({encoding})")
        return "Valid" if result.valid else ("; ".join(result.errors) or "Invalid")

    def validate_spdx_json(self, file_path: str) -> str:
        return self._forced(file_path, "spdx", "json")

    def validate_spdx_xml(self, file_path: str) -> str:
        return self._forced(file_path, "spdx", "xml")

    def validate_cyclonedx_json(self, file_path: str) -> str:
        return self._forced(file_path, "cyclonedx", "json")

    def validate_cyclonedx_xml(self, file_path: str) -> str:
        return self._forced(file_path, "cyclonedx", "xml")
