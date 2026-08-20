"""Version-aware structural validation for SPDX and CycloneDX.

This replaces the original hand-rolled validator, which (a) always validated
CycloneDX JSON against the 1.4 schema regardless of the document's real version,
and (b) stubbed XML validation to always return "Valid". Here the declared
version is detected first, then the document is validated against the matching
schema using mature libraries (N3):

    - CycloneDX 1.0-1.6 (JSON + XML)  -> cyclonedx-python-lib schema validators
    - SPDX 2.2 / 2.3 (json/xml/tagvalue/rdf/yaml) -> spdx-tools full validator
    - SPDX 3.0 (JSON-LD) -> spdx-tools spdx3 (best-effort; see notes)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .detect import Detection, detect_file, spdx3_types


@dataclass
class SchemaResult:
    valid: bool
    sbom_format: str
    spec_version: str
    encoding: str
    errors: list[str] = field(default_factory=list)
    # True when validation was structural/best-effort rather than full schema
    # (currently only SPDX 3.0, whose tooling is still experimental).
    partial: bool = False

    def __str__(self) -> str:  # human-friendly one-liner
        head = f"{self.sbom_format} {self.spec_version} ({self.encoding})"
        if self.valid:
            return f"Valid: {head}" + (" [structural only]" if self.partial else "")
        return f"Invalid: {head}\n  - " + "\n  - ".join(self.errors)


# ---- CycloneDX ---------------------------------------------------------------

def _cdx_schema_version(version: str):
    from cyclonedx.schema import SchemaVersion

    parts = version.split(".")
    if len(parts) < 2:
        raise ValueError(f"Unrecognized CycloneDX version: {version!r}")
    name = f"V{int(parts[0])}_{int(parts[1])}"
    try:
        return getattr(SchemaVersion, name)
    except AttributeError as exc:
        supported = [s.name.replace("V", "").replace("_", ".") for s in SchemaVersion]
        raise ValueError(
            f"CycloneDX {version} is not supported by the installed library "
            f"(supported: {', '.join(sorted(supported))})"
        ) from exc


def _validate_cyclonedx(text: str, det: Detection) -> SchemaResult:
    from cyclonedx.schema import OutputFormat
    from cyclonedx.validation import make_schemabased_validator

    out = OutputFormat.JSON if det.encoding == "json" else OutputFormat.XML
    try:
        schema_version = _cdx_schema_version(det.spec_version)
    except ValueError as exc:
        return SchemaResult(False, det.sbom_format, det.spec_version, det.encoding, [str(exc)])

    validator = make_schemabased_validator(out, schema_version)
    problem = validator.validate_str(text)
    if problem is None:
        return SchemaResult(True, det.sbom_format, det.spec_version, det.encoding)
    return SchemaResult(False, det.sbom_format, det.spec_version, det.encoding, [str(problem)])


# ---- SPDX --------------------------------------------------------------------

def _validate_spdx_2x(path: str, det: Detection) -> SchemaResult:
    from spdx_tools.spdx.validation.document_validator import (
        validate_full_spdx_document,
    )

    from .parsers import _spdx_parse

    try:
        document = _spdx_parse(path, det)
    # spdx-tools raises SPDXParsingError and friends, and the set is not stable
    # across releases. A malformed document must come back as a parse failure,
    # never as a traceback, so the catch stays broad deliberately.
    except Exception as exc:  # noqa: BLE001
        return SchemaResult(False, det.sbom_format, det.spec_version, det.encoding,
                            [f"parse error: {exc}"])
    problems = validate_full_spdx_document(document)
    detected = document.creation_info.spdx_version.replace("SPDX-", "")
    if not problems:
        return SchemaResult(True, det.sbom_format, detected, det.encoding)
    msgs = [p.validation_message for p in problems]
    return SchemaResult(False, det.sbom_format, detected, det.encoding, msgs)


def _validate_spdx_3x(path: str, det: Detection) -> SchemaResult:
    # SPDX 3.0 tooling is still experimental, so this is a structural check of the
    # JSON-LD shape rather than a schema validation. Reading 3.0 payloads through
    # spdx-tools is not stable across releases, so we deliberately do not depend
    # on its internals here.
    import json
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return SchemaResult(False, det.sbom_format, det.spec_version, det.encoding,
                            [f"parse error: {exc}"], partial=True)

    errors: list[str] = []
    if "@context" not in data:
        errors.append("SPDX 3.0 JSON-LD document missing @context")
    graph = data.get("@graph")
    if not isinstance(graph, list) or not graph:
        errors.append("SPDX 3.0 JSON-LD document missing a non-empty @graph")
    else:
        types = set().union(*(spdx3_types(n) for n in graph if isinstance(n, dict))) \
            if graph else set()
        if "SpdxDocument" not in types and "CreationInfo" not in types:
            errors.append("SPDX 3.0 @graph contains no SpdxDocument/CreationInfo element")
    return SchemaResult(not errors, det.sbom_format, det.spec_version, det.encoding,
                        errors, partial=True)


# ---- public entrypoint -------------------------------------------------------

def validate_schema(path: str, detection: Detection | None = None) -> SchemaResult:
    """Detect the SBOM's real format/version, then validate against that schema."""
    det = detection or detect_file(path)

    if det.sbom_format == "cyclonedx":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        return _validate_cyclonedx(text, det)

    if det.sbom_format == "spdx":
        if det.version_major() >= 3:
            return _validate_spdx_3x(path, det)
        return _validate_spdx_2x(path, det)

    return SchemaResult(False, det.sbom_format, det.spec_version, det.encoding,
                        [f"unsupported format: {det.sbom_format}"])
