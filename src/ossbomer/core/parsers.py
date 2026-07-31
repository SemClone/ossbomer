"""Parse SBOM files into the canonical :class:`~ossbomer.core.ir.Sbom` IR.

CycloneDX JSON is mapped directly from the document (json is a mature parser).
SPDX (all encodings) is parsed with spdx-tools and mapped from its model, so no
XML is hand-rolled (N3). The IR exposes components and the dependency graph so
rules can iterate per component and per dependency (R8).
"""
from __future__ import annotations

import json
from typing import Any

from .detect import Detection, detect_file
from .ir import Component, Document, Sbom


class ParseError(ValueError):
    pass


def parse_file(path: str, detection: Detection | None = None) -> Sbom:
    det = detection or detect_file(path)
    if det.sbom_format == "cyclonedx":
        if det.encoding == "json":
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return _cyclonedx_json_to_ir(data, det, path)
        if det.encoding == "xml":
            return _cyclonedx_xml_to_ir(path, det)
        raise ParseError(f"Unsupported CycloneDX encoding for IR: {det.encoding}")
    if det.sbom_format == "spdx":
        if det.version_major() >= 3:
            return _spdx3_json_to_ir(path, det)
        return _spdx2_to_ir(path, det)
    raise ParseError(f"Unsupported format: {det.sbom_format}")


# ---- CycloneDX ---------------------------------------------------------------

def _cdx_licenses(entry: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for lic in entry.get("licenses", []) or []:
        if "expression" in lic:
            out.append(lic["expression"])
        elif "license" in lic:
            lo = lic["license"]
            out.append(lo.get("id") or lo.get("name") or "")
    return [x for x in out if x]


def _cdx_component(entry: dict[str, Any]) -> Component:
    supplier = entry.get("supplier") or {}
    return Component(
        bom_ref=entry.get("bom-ref"),
        name=entry.get("name"),
        version=entry.get("version"),
        type=entry.get("type"),
        purl=entry.get("purl"),
        cpe=entry.get("cpe"),
        supplier=supplier.get("name") if isinstance(supplier, dict) else None,
        author=entry.get("author"),
        publisher=entry.get("publisher"),
        licenses=_cdx_licenses(entry),
        hashes={h["alg"].lower(): h["content"] for h in entry.get("hashes", []) or []
                if "alg" in h and "content" in h},
        external_refs=entry.get("externalReferences", []) or [],
        properties={p["name"]: p.get("value") for p in entry.get("properties", []) or []
                    if "name" in p},
        raw=entry,
    )


def _cyclonedx_json_to_ir(data: dict[str, Any], det: Detection, path: str) -> Sbom:
    meta = data.get("metadata", {}) or {}
    tools = meta.get("tools", {})
    tool_names: list[str] = []
    if isinstance(tools, dict):  # 1.5+ shape: {"components":[...], "services":[...]}
        for t in tools.get("components", []) or []:
            tool_names.append(t.get("name", ""))
    elif isinstance(tools, list):  # <=1.4 shape
        for t in tools:
            tool_names.append(t.get("name", "") if isinstance(t, dict) else str(t))

    # Human / organizational authorship. CycloneDX carries this separately from
    # `metadata.tools`, so it has to be read separately -- a document whose author
    # is a person or an organization has no tool entry at all.
    author_names: list[str] = []
    for a in meta.get("authors", []) or []:
        if isinstance(a, dict):
            name = a.get("name") or a.get("email")
            if name:
                author_names.append(str(name))
        elif a:
            author_names.append(str(a))

    # 1.6 renamed `metadata.manufacture` to `metadata.manufacturer`; accept both so
    # the mapping holds across the whole 1.3-1.6 range we claim to support.
    manufacturer = meta.get("manufacturer") or meta.get("manufacture")
    if isinstance(manufacturer, dict) and manufacturer.get("name"):
        author_names.append(str(manufacturer["name"]))

    tool_names = [t for t in tool_names if t]

    doc_supplier = (meta.get("supplier") or {}).get("name") if isinstance(meta.get("supplier"), dict) else None
    document = Document(
        name=(meta.get("component") or {}).get("name"),
        namespace=data.get("serialNumber"),
        timestamp=meta.get("timestamp"),
        tools=tool_names,
        # Mirrors the SPDX mapping, where `creators` holds every creator -- person,
        # organization and tool -- and `tools` is the tool-only subset.
        creators=author_names + tool_names,
        supplier=doc_supplier,
        signed="signature" in data or "signature" in meta,
        raw=meta,
    )

    components = [_cdx_component(c) for c in data.get("components", []) or []]

    deps: dict[str, list[str]] = {}
    for d in data.get("dependencies", []) or []:
        ref = d.get("ref")
        if ref is not None:
            deps[ref] = list(d.get("dependsOn", []) or [])

    return Sbom(
        sbom_format="cyclonedx", spec_version=det.spec_version, encoding="json",
        document=document, components=components, dependencies=deps,
        source_path=path, raw=data,
    )


def _cyclonedx_xml_to_ir(path: str, det: Detection) -> Sbom:
    # Convert XML to the CycloneDX JSON shape via the mature library, then reuse
    # the JSON mapper — avoids hand-rolled XML (N3).
    from cyclonedx.model.bom import Bom
    from cyclonedx.output import make_outputter
    from cyclonedx.schema import OutputFormat, SchemaVersion
    from lxml import etree

    root = etree.parse(path).getroot()
    bom = Bom.from_xml(root)  # type: ignore[attr-defined]
    sv = getattr(SchemaVersion, f"V{det.spec_version.replace('.', '_')}")
    as_json = make_outputter(bom, OutputFormat.JSON, sv).output_as_string()
    data = json.loads(as_json)
    sbom = _cyclonedx_json_to_ir(data, det, path)
    sbom.encoding = "xml"
    return sbom


# ---- SPDX 2.x ----------------------------------------------------------------

def _spdx2_to_ir(path: str, det: Detection) -> Sbom:
    from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse

    doc = spdx_parse(path)
    ci = doc.creation_info

    components: list[Component] = []
    for pkg in doc.packages:
        purl = None
        for ref in getattr(pkg, "external_references", []) or []:
            if getattr(ref, "reference_type", "") == "purl":
                purl = ref.locator
                break
        licenses = []
        for attr in ("license_concluded", "license_declared"):
            val = getattr(pkg, attr, None)
            if val is not None:
                licenses.append(str(val))
        components.append(Component(
            bom_ref=pkg.spdx_id,
            name=pkg.name,
            version=getattr(pkg, "version", None),
            purl=purl,
            supplier=str(pkg.supplier) if getattr(pkg, "supplier", None) else None,
            author=str(pkg.originator) if getattr(pkg, "originator", None) else None,
            licenses=[x for x in licenses if x and x != "None"],
            hashes={c.algorithm.name.lower(): c.value for c in getattr(pkg, "checksums", []) or []},
            raw={"spdx_id": pkg.spdx_id},
        ))

    deps: dict[str, list[str]] = {}
    for rel in doc.relationships:
        if getattr(rel.relationship_type, "name", "") in ("DEPENDS_ON", "DESCRIBES", "CONTAINS"):
            related = rel.related_spdx_element_id
            # SPDX permits NONE and NOASSERTION where an element id would go.
            # spdx-tools returns those as SpdxNone / SpdxNoAssertion objects, not
            # strings. They are statements about the absence of a relationship,
            # so they are not edges -- letting them through would put non-string
            # sentinels into the dependency graph, where they would be compared
            # against real component refs by dependency_completeness.
            if not isinstance(related, str):
                continue
            deps.setdefault(rel.spdx_element_id, []).append(related)

    document = Document(
        name=ci.name,
        namespace=ci.document_namespace,
        timestamp=ci.created.isoformat() if ci.created else None,
        creators=[str(c) for c in ci.creators],
        tools=[str(c) for c in ci.creators if str(c).startswith("Tool:")],
        data_license=ci.data_license,
    )
    return Sbom(
        sbom_format="spdx", spec_version=ci.spdx_version.replace("SPDX-", ""),
        encoding=det.encoding, document=document, components=components,
        dependencies=deps, source_path=path,
    )


# ---- SPDX 3.0 (best-effort JSON-LD) ------------------------------------------

def _spdx3_json_to_ir(path: str, det: Detection) -> Sbom:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    graph = data.get("@graph", []) if isinstance(data, dict) else []
    components: list[Component] = []
    document = Document(raw=data if isinstance(data, dict) else {})
    for node in graph:
        if not isinstance(node, dict):
            continue
        ntype = str(node.get("type", "")).split(":")[-1]
        if ntype in ("software_Package", "software_File", "Package"):
            components.append(Component(
                bom_ref=node.get("spdxId"),
                name=node.get("name"),
                version=node.get("software_packageVersion") or node.get("packageVersion"),
                raw=node,
            ))
        elif ntype == "SpdxDocument":
            document.name = node.get("name")
            document.namespace = node.get("spdxId")
        elif ntype == "CreationInfo":
            document.timestamp = node.get("created")
            document.creators = list(node.get("createdBy", []) or [])
    return Sbom(
        sbom_format="spdx", spec_version=det.spec_version, encoding="json",
        document=document, components=components, source_path=path,
        raw=data if isinstance(data, dict) else {},
    )
