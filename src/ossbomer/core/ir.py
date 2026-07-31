"""Canonical SBOM intermediate representation (IR).

All layers (conformance, oslc, scoring) operate on this normalized model so they
never re-parse the source document. The IR is format-agnostic: SPDX and CycloneDX
are both mapped into the same shape, with the original spec format/version
retained for rules that need to branch on them (R8: iterate per component and per
dependency).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoids a cycle: licenses.py needs is_null_value from here
    from .licenses import LicenseDeclaration

# Sentinel-ish tokens that mean "explicitly no value" in SBOMs.
NULL_TOKENS = frozenset({"", "noassertion", "none", "n/a", "unknown"})


def is_null_value(value: str | None) -> bool:
    """True if a string field is empty or an explicit null token (NOASSERTION/NONE)."""
    if value is None:
        return True
    return str(value).strip().lower() in NULL_TOKENS


@dataclass
class Component:
    """A single component/package in the SBOM."""

    bom_ref: str | None = None
    name: str | None = None
    version: str | None = None
    type: str | None = None
    purl: str | None = None
    cpe: str | None = None
    supplier: str | None = None
    author: str | None = None
    publisher: str | None = None
    # Effective license strings: the normalized SPDX form where one could be
    # resolved, otherwise the raw text. This is what rules and policy see.
    licenses: list[str] = field(default_factory=list)
    # The full record for each declaration: what the document said, which slot
    # it came from, and how it normalized. Lets a rule tell "unpinnable free
    # text" apart from "valid expression in the wrong field", which the flat
    # `licenses` list above collapses together.
    license_declarations: list[LicenseDeclaration] = field(default_factory=list)
    # alg (lowercased) -> hash value
    hashes: dict[str, str] = field(default_factory=dict)
    external_refs: list[dict[str, Any]] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    # Untouched source mapping for this component (rules may reach in for edge cases).
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        """Best available human-readable identifier, for issue locations.

        Ordered most to least specific. Written as explicit branches rather than
        an `or` chain: an f-string is always truthy, so a chain would make every
        fallback after it unreachable and yield "None@None" for a component with
        no name.
        """
        if self.purl:
            return self.purl
        if self.cpe:
            return self.cpe
        if self.name:
            return f"{self.name}@{self.version}" if self.version else self.name
        return self.bom_ref or "<unknown>"


@dataclass
class Document:
    """Document/BOM-level metadata."""

    name: str | None = None
    namespace: str | None = None
    timestamp: str | None = None
    # Everyone credited with creating the SBOM: people, organizations and tools.
    # This is what "author of SBOM data" rules check.
    creators: list[str] = field(default_factory=list)
    # The tool-only subset of `creators`.
    tools: list[str] = field(default_factory=list)
    # Versions of the tools in `tools`, kept as a parallel list rather than
    # folded into the tool strings so a rule can check "is a version declared"
    # without parsing names apart. CISA 2026 makes SBOM Tool Version its own
    # minimum element, distinct from SBOM Tool Name.
    tool_versions: list[str] = field(default_factory=list)
    # Version of the SBOM document itself (CISA 2026 "SBOM Version"), distinct
    # from the spec version of the data format and from the version of the
    # component the SBOM describes.
    sbom_version: str | None = None
    # Software lifecycle phase(s) the SBOM was generated in (CISA 2026 "SBOM
    # Generation Context"): "pre-build", "build", "post-build" and friends.
    lifecycles: list[str] = field(default_factory=list)
    supplier: str | None = None
    data_license: str | None = None
    # True when the document carries a signature envelope (COSE/JWS/x509 detached).
    signed: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Sbom:
    """Normalized SBOM.

    Attributes:
        sbom_format: "spdx" or "cyclonedx".
        spec_version: e.g. "1.6", "2.3", "3.0.1".
        encoding: "json", "xml", "tagvalue", "rdf", or "yaml".
    """

    sbom_format: str
    spec_version: str
    encoding: str
    document: Document = field(default_factory=Document)
    components: list[Component] = field(default_factory=list)
    # dependency graph: component ref -> list of refs it depends on.
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    source_path: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def version_tuple(self) -> tuple[int, ...]:
        parts: list[int] = []
        for chunk in self.spec_version.split("."):
            try:
                parts.append(int(chunk))
            except ValueError:
                break
        return tuple(parts)
