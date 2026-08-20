"""Parse SBOM files into the canonical :class:`~ossbomer.core.ir.Sbom` IR.

CycloneDX JSON is mapped directly from the document (json is a mature parser).
SPDX (all encodings) is parsed with spdx-tools and mapped from its model, so no
XML is hand-rolled (N3). The IR exposes components and the dependency graph so
rules can iterate per component and per dependency (R8).
"""
from __future__ import annotations

import json
from datetime import timezone
from typing import Any

from .detect import Detection, detect_file, spdx3_id, spdx3_types
from .ir import Component, Document, File, Sbom
from .licenses import (
    SOURCE_EXPRESSION,
    SOURCE_ID,
    SOURCE_NAME,
    SOURCE_SPDX_FIELD,
    LicenseDeclaration,
    normalize,
)


class ParseError(ValueError):
    pass


# SPDX 2.3 §7.11.2 defines both, and documents in the wild use both: `cpe22Type`
# for the CPE 2.2 URI binding, `cpe23Type` for the 2.3 formatted string. A
# document declaring only the older one still declares an identifier.
SPDX_CPE_REF_TYPES = ("cpe23Type", "cpe22Type")


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

def _cdx_licenses(entry: dict[str, Any]) -> list[LicenseDeclaration]:
    """Read all three CycloneDX license slots, keeping track of which is which.

    `expression` and `license.id` are SPDX-typed; `license.name` is free text by
    specification, used when the generator could not pin an identifier. Flattening
    them lost that distinction, so free text was reported as bad expression
    syntax and a well-formed expression in the `name` slot passed silently.
    """
    out: list[LicenseDeclaration] = []
    for lic in entry.get("licenses", []) or []:
        if not isinstance(lic, dict):
            continue
        if lic.get("expression"):
            out.append(normalize(str(lic["expression"]), SOURCE_EXPRESSION))
            continue
        lo = lic.get("license")
        if not isinstance(lo, dict):
            continue
        if lo.get("id"):
            out.append(normalize(str(lo["id"]), SOURCE_ID))
        elif lo.get("name"):
            out.append(normalize(str(lo["name"]), SOURCE_NAME))
    return out


def _cdx_file(entry: dict[str, Any]) -> File:
    """A CycloneDX `type: file` component, as a file entry.

    `name` carries the path in CycloneDX, where SPDX uses `fileName`; both land
    on `File.name` so one rule serves both formats.
    """
    declarations = _cdx_licenses(entry)
    return File(
        spdx_id=entry.get("bom-ref"),
        name=entry.get("name"),
        hashes={h["alg"].lower(): h["content"] for h in entry.get("hashes", []) or []
                if "alg" in h and "content" in h},
        licenses=[d.effective for d in declarations if d.effective],
        copyright=entry.get("copyright"),
        raw=entry,
    )


def _cdx_component(entry: dict[str, Any]) -> Component:
    supplier = entry.get("supplier") or {}
    declarations = _cdx_licenses(entry)
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
        licenses=[d.effective for d in declarations if d.effective],
        license_declarations=declarations,
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
    tool_versions: list[str] = []
    if isinstance(tools, dict):  # 1.5+ shape: {"components":[...], "services":[...]}
        for t in tools.get("components", []) or []:
            tool_names.append(t.get("name", ""))
            if t.get("version"):
                tool_versions.append(str(t["version"]))
    elif isinstance(tools, list):  # <=1.4 shape
        for t in tools:
            if isinstance(t, dict):
                tool_names.append(t.get("name", ""))
                if t.get("version"):
                    tool_versions.append(str(t["version"]))
            else:
                tool_names.append(str(t))

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

    # `metadata.lifecycles` (1.5+) is CycloneDX's native expression of the phase
    # the SBOM was produced in. Entries are either a predefined `phase` or a
    # free-text `name`, and both satisfy CISA 2026 SBOM Generation Context.
    lifecycles: list[str] = []
    for lc in meta.get("lifecycles", []) or []:
        if isinstance(lc, dict):
            value = lc.get("phase") or lc.get("name")
            if value:
                lifecycles.append(str(value))
        elif lc:
            lifecycles.append(str(lc))

    document = Document(
        name=(meta.get("component") or {}).get("name"),
        namespace=data.get("serialNumber"),
        timestamp=meta.get("timestamp"),
        tools=tool_names,
        tool_versions=tool_versions,
        # Top-level `version` is the revision of this BOM document, which is what
        # CISA 2026 calls SBOM Version. Not to be confused with `specVersion`
        # (the data format version) or `metadata.component.version`.
        sbom_version=str(data["version"]) if data.get("version") is not None else None,
        lifecycles=lifecycles,
        # Mirrors the SPDX mapping, where `creators` holds every creator -- person,
        # organization and tool -- and `tools` is the tool-only subset.
        creators=author_names + tool_names,
        supplier=doc_supplier,
        signed="signature" in data or "signature" in meta,
        raw=meta,
    )

    components = [_cdx_component(c) for c in data.get("components", []) or []]
    # CycloneDX has no separate files section: a file is a component whose
    # `type` is "file". Mirrored into `files` rather than moved out of
    # `components`, so file rules can reach them without changing what every
    # existing component rule sees.
    # `str()` before `.lower()`: a schema-invalid document can carry a non-string
    # `type`, and the parser has to survive long enough for the schema gate to
    # report that. Crashing here would replace a clear schema failure with a
    # traceback.
    files = [_cdx_file(c) for c in data.get("components", []) or []
             if str(c.get("type") or "").lower() == "file"]

    deps: dict[str, list[str]] = {}
    for d in data.get("dependencies", []) or []:
        ref = d.get("ref")
        if ref is not None:
            deps[ref] = list(d.get("dependsOn", []) or [])

    return Sbom(
        sbom_format="cyclonedx", spec_version=det.spec_version, encoding="json",
        document=document, components=components, files=files, dependencies=deps,
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

def _spdx_parse(path: str, det: Detection):
    """Parse an SPDX 2.x document, preferring our detection over the filename.

    `parse_anything.parse_file` dispatches on `file_name_to_format(path)`, so it
    re-decides the encoding from the extension and can contradict `detect_file`,
    which reads the bytes. A tag-value document named `.json` detected correctly
    as `spdx 2.2 tagvalue` then failed with "Expecting value: line 1 column 1".
    SBOMs arrive from APIs, build artifacts and downloads with wrong or absent
    extensions, and the answer should not depend on the name.

    parse_anything is still tried first: it distinguishes `.rdf.xml` from `.xml`,
    a split our `encoding` field flattens to "xml". Only when it fails do we
    dispatch on what the bytes said.
    """
    from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse

    try:
        return spdx_parse(path)
    except Exception as by_name:
        parsers = {}
        try:
            from spdx_tools.spdx.parser.json import json_parser
            from spdx_tools.spdx.parser.tagvalue import tagvalue_parser
            from spdx_tools.spdx.parser.xml import xml_parser
            from spdx_tools.spdx.parser.yaml import yaml_parser
            parsers = {"json": json_parser, "tagvalue": tagvalue_parser,
                       "xml": xml_parser, "yaml": yaml_parser}
        except ImportError:  # pragma: no cover - spdx-tools always present
            raise by_name from None
        chosen = parsers.get(det.encoding)
        if chosen is None:
            raise
        try:
            return chosen.parse_from_file(path)
        # Broad by design: this is a fallback for a document the name-based
        # parser already rejected. Whatever the content-based parser raises,
        # the extension-based error is the more familiar one to report, and
        # neither should surface as a traceback.
        except Exception:  # noqa: BLE001
            raise by_name from None


def _spdx2_to_ir(path: str, det: Detection) -> Sbom:
    doc = _spdx_parse(path, det)
    ci = doc.creation_info

    components: list[Component] = []
    for pkg in doc.packages:
        # SPDX 2.3 §7.11 carries both identifiers in the same list, told apart by
        # reference type: `purl` under PACKAGE-MANAGER, `cpe22Type`/`cpe23Type`
        # under SECURITY. Reading only the first meant every SPDX component came
        # out with `cpe=None`, so the same component parsed from SPDX and from
        # CycloneDX produced different IR. Both are scanned, and neither loop
        # stops the other: a package may legitimately declare both.
        purl = None
        cpe = None
        for ref in getattr(pkg, "external_references", []) or []:
            ref_type = getattr(ref, "reference_type", "")
            if purl is None and ref_type == "purl":
                purl = ref.locator
            elif cpe is None and ref_type in SPDX_CPE_REF_TYPES:
                cpe = ref.locator
            if purl is not None and cpe is not None:
                break
        declarations = []
        for attr in ("license_concluded", "license_declared"):
            val = getattr(pkg, attr, None)
            if val is not None and str(val) not in ("None", ""):
                declarations.append(normalize(str(val), SOURCE_SPDX_FIELD))
        components.append(Component(
            bom_ref=pkg.spdx_id,
            name=pkg.name,
            version=getattr(pkg, "version", None),
            purl=purl,
            cpe=cpe,
            supplier=str(pkg.supplier) if getattr(pkg, "supplier", None) else None,
            author=str(pkg.originator) if getattr(pkg, "originator", None) else None,
            licenses=[d.effective for d in declarations if d.effective],
            license_declarations=declarations,
            hashes={c.algorithm.name.lower(): c.value for c in getattr(pkg, "checksums", []) or []},
            raw={"spdx_id": pkg.spdx_id},
        ))

    # SPDX 2.3 §8 makes the files section optional, and §8.4 makes FileChecksum
    # mandatory on any entry that is there. Nothing read it, so a rule about file
    # integrity had nowhere to point.
    files: list[File] = []
    for f in getattr(doc, "files", []) or []:
        declared = [getattr(f, "license_concluded", None)]
        declared += list(getattr(f, "license_info_in_file", []) or [])
        files.append(File(
            spdx_id=getattr(f, "spdx_id", None),
            name=getattr(f, "name", None),
            hashes={c.algorithm.name.lower(): c.value
                    for c in getattr(f, "checksums", []) or []},
            licenses=[str(lic) for lic in declared
                      if lic is not None and str(lic) not in ("None", "")],
            copyright=(str(f.copyright_text)
                       if getattr(f, "copyright_text", None) is not None else None),
            raw={"spdx_id": getattr(f, "spdx_id", None)},
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

    # SPDX 2.x has no separate field for a tool's version: the convention in
    # section 6.8 is a single "Tool: name-version" creator string. Split on the
    # last hyphen so the version is checkable on its own, and record nothing
    # when the creator omits it rather than inventing a value.
    tool_creators = [str(c) for c in ci.creators if str(c).startswith("Tool:")]
    tool_versions: list[str] = []
    for entry in tool_creators:
        name_part = entry.split(":", 1)[1].strip()
        if "-" in name_part:
            candidate = name_part.rsplit("-", 1)[1].strip()
            if candidate:
                tool_versions.append(candidate)

    # SPDX 2.x section 6.9 defines `created` as UTC, so spdx-tools parses it
    # into a naive datetime and drops the `Z`. Formatting that naive value
    # yields a string with no offset, which rfc3339_utc is then right to
    # reject -- a tool artefact that failed every conformant SPDX document on
    # any profile with a timestamp rule. Restore the UTC the spec guarantees.
    created = ci.created
    if created is not None and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    document = Document(
        name=ci.name,
        namespace=ci.document_namespace,
        timestamp=created.isoformat() if created else None,
        creators=[str(c) for c in ci.creators],
        tools=tool_creators,
        tool_versions=tool_versions,
        # SPDX 2.x has no document-version or lifecycle-phase field, so
        # `sbom_version` and `lifecycles` stay unset here by design. A profile
        # rule for either can only be SHOULD if it is to be satisfiable on SPDX.
        data_license=ci.data_license,
    )
    return Sbom(
        sbom_format="spdx", spec_version=ci.spdx_version.replace("SPDX-", ""),
        encoding=det.encoding, document=document, components=components,
        files=files, dependencies=deps, source_path=path,
    )


# ---- SPDX 3.0 (best-effort JSON-LD) ------------------------------------------

def _spdx3_hashes(node: dict[str, Any]) -> dict[str, str]:
    """Digests from a 3.0 element's `verifiedUsing` integrity methods.

    3.0 replaced 2.x's `checksums` with a list of IntegrityMethod objects, of
    which `Hash` is one; the algorithm may arrive bare (`sha256`) or namespaced
    (`hashAlgorithm_sha256`), so the prefix is trimmed and the result lower-cased
    to match `Component.hashes` and `File.hashes` elsewhere.

    Applied to files only. Components on 3.0 documents carry no hashes today,
    and giving them some would change what existing hash rules see on those
    documents -- a separate change with its own blast radius.
    """
    hashes: dict[str, str] = {}
    # JSON-LD compaction collapses a single-element array to a bare object
    # unless the context pins `@container: @set`, so one hash may arrive either
    # way. Iterating the bare object would walk its keys and find no dicts,
    # leaving the file looking unchecksummed when it carried one.
    raw = node.get("verifiedUsing") or []
    for entry in (raw if isinstance(raw, list) else [raw]):
        if not isinstance(entry, dict):
            continue
        if "Hash" not in spdx3_types(entry):
            continue
        # Only the `hashAlgorithm_` prefix comes off. Splitting on every
        # underscore turned `sha3_256` into `256`, which is a different
        # algorithm and one `hash_algorithm_in_set` would not recognise.
        algorithm = str(entry.get("algorithm", "")).rsplit("/", 1)[-1].rsplit("#", 1)[-1]
        algorithm = algorithm.removeprefix("hashAlgorithm_")
        algorithm = algorithm.strip().lower()
        value = entry.get("hashValue")
        if algorithm and value:
            hashes[algorithm] = str(value)
    return hashes


def _spdx3_json_to_ir(path: str, det: Detection) -> Sbom:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    graph = data.get("@graph", []) if isinstance(data, dict) else []
    components: list[Component] = []
    files: list[File] = []
    document = Document(raw=data if isinstance(data, dict) else {})
    for node in graph:
        if not isinstance(node, dict):
            continue
        ntypes = spdx3_types(node)
        node_id = spdx3_id(node)
        if "File" in ntypes:
            # Mirrored, not moved: these already reach `components` below, and
            # taking them out would change what every existing component rule
            # sees on a 3.0 document.
            files.append(File(
                spdx_id=node_id,
                name=node.get("name"),
                hashes=_spdx3_hashes(node),
                # `software_copyrightText` is a direct property of a 3.0
                # SoftwareArtifact, so it costs a lookup and the SPDX 2.x and
                # CycloneDX paths both fill it -- leaving it empty here would
                # make the same file answer differently by format.
                #
                # `licenses` stays empty on 3.0. Licensing there is not a field:
                # it is a relationship to a separate license element, which the
                # component path does not resolve either. Reading it is a
                # separate change, not something to half-do for files alone.
                copyright=node.get("software_copyrightText"),
                raw=node,
            ))
        if ntypes & {"Package", "File"}:
            components.append(Component(
                bom_ref=node_id,
                name=node.get("name"),
                version=node.get("software_packageVersion") or node.get("packageVersion"),
                raw=node,
            ))
        elif "SpdxDocument" in ntypes:
            document.name = node.get("name")
            document.namespace = node_id
        elif "CreationInfo" in ntypes:
            document.timestamp = node.get("created")
            document.creators = list(node.get("createdBy", []) or [])
    return Sbom(
        sbom_format="spdx", spec_version=det.spec_version, encoding="json",
        document=document, components=components, files=files, source_path=path,
        raw=data if isinstance(data, dict) else {},
    )
