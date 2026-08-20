"""Format / version / encoding detection for SBOM files.

Detection is intentionally cheap and dependency-free (peek the bytes), so callers
can pick the right mature-library parser/validator afterwards. It never trusts a
hardcoded version — the actual declared version is extracted from the document.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

CDX_NS_RE = re.compile(r"cyclonedx.org/schema/bom/(\d+\.\d+)")
SPDX_TAG_VER_RE = re.compile(r"SPDXVersion:\s*SPDX-(\d+\.\d+)")
SPDX_CTX_VER_RE = re.compile(r"spdx.org/rdf/(\d+\.\d+(?:\.\d+)?)")

# SPDX YAML carries the same property names as SPDX JSON -- camelCase, lowercase
# initial -- whereas tag-value uses CamelCase tags ("spdxVersion" vs
# "SPDXVersion"). `SPDXID:` is spelled identically in both and so cannot tell
# them apart, which is why these keys are matched instead.
SPDX_YAML_KEY_RE = re.compile(
    r"^[ \t]*(spdxVersion|dataLicense|documentNamespace|creationInfo|"
    r"hasExtractedLicensingInfos|documentDescribes)[ \t]*:",
    re.MULTILINE,
)
SPDX_YAML_VER_RE = re.compile(
    r"^[ \t]*spdxVersion[ \t]*:[ \t]*[\"']?SPDX-(\d+\.\d+)", re.MULTILINE
)


class DetectionError(ValueError):
    """Raised when the file is not a recognizable SPDX or CycloneDX document."""


def spdx3_types(node: dict) -> set[str]:
    """Every class name a 3.0 element declares, however the JSON-LD spells it.

    One graph has more than one valid shape. Compacted against the SPDX context a
    node reads `"type": "software_File"`; with `@type` retained it reads a full
    IRI, and JSON-LD allows a list of them. Namespace and profile prefixes are
    trimmed either way, so `software_File`, `File` and the full IRI all answer
    `File`.

    A set rather than one name: `@type` may legitimately carry a node's whole
    ancestry, and the first entry is not the authoritative one. Reading only
    `raw[0]` turned `["…/Core/Element", "…/Software/File"]` into `Element`, so a
    perfectly good file node was skipped and the schema gate then reported the
    document as missing elements it declared.

    Lives here rather than in the parser because the schema gate needs the same
    answer: reading a shape the gate then rejects would report a document we
    understood perfectly well as unreadable.
    """
    raw = node.get("type") or node.get("@type") or ""
    values = raw if isinstance(raw, list) else [raw]
    names = set()
    for value in values:
        name = str(value).rsplit("/", 1)[-1].rsplit("#", 1)[-1]
        name = name.split(":")[-1].split("_")[-1]
        if name:
            names.add(name)
    return names


def spdx3_id(node: dict) -> str | None:
    """A 3.0 element's identifier, compacted (`spdxId`) or expanded (`@id`)."""
    value = node.get("spdxId") or node.get("@id")
    return str(value) if value is not None else None


@dataclass(frozen=True)
class Detection:
    sbom_format: str  # "spdx" | "cyclonedx"
    spec_version: str  # e.g. "1.6", "2.3", "3.0.1"
    encoding: str  # "json" | "xml" | "tagvalue" | "yaml" (yaml is SPDX-only)

    def version_major(self) -> int:
        try:
            return int(self.spec_version.split(".")[0])
        except (ValueError, IndexError):
            return 0


def _normalize_spdx_version(raw: str) -> str:
    # "SPDX-2.3" -> "2.3"; "3.0.1" -> "3.0.1"
    return raw.replace("SPDX-", "").strip()


def detect_text(text: str) -> Detection:
    stripped = text.lstrip()

    # `"" in "{["` is True, so an empty document would otherwise be reported as
    # malformed JSON rather than as an empty file.
    if not stripped:
        raise DetectionError("Document is empty.")

    # --- JSON (CycloneDX or SPDX 2.x JSON or SPDX 3.x JSON-LD) ---
    if stripped[:1] in "{[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DetectionError(f"Looks like JSON but failed to parse: {exc}") from exc
        return _detect_json(data)

    # --- XML (CycloneDX; SPDX RDF/XML) ---
    if stripped[:1] == "<":
        ns = CDX_NS_RE.search(text)
        if ns:
            return Detection("cyclonedx", ns.group(1), "xml")
        if "spdx" in text.lower():
            ctx = SPDX_CTX_VER_RE.search(text)
            return Detection("spdx", ctx.group(1) if ctx else "2.3", "xml")
        raise DetectionError("XML document is neither CycloneDX nor SPDX.")

    # --- SPDX YAML ---
    # Checked before tag-value: both spell `SPDXID:` the same way, so a YAML
    # document falls into the tag-value branch unless it is claimed here first.
    if SPDX_YAML_KEY_RE.search(text):
        ver = SPDX_YAML_VER_RE.search(text)
        return Detection("spdx", _normalize_spdx_version(ver.group(1)) if ver else "2.3", "yaml")

    # --- SPDX tag-value ---
    tag = SPDX_TAG_VER_RE.search(text)
    if tag or "SPDXID:" in text or "DocumentNamespace:" in text:
        return Detection("spdx", _normalize_spdx_version(tag.group(1)) if tag else "2.3", "tagvalue")

    raise DetectionError("Unrecognized SBOM format (not CycloneDX or SPDX).")


def _detect_json(data: object) -> Detection:
    if isinstance(data, dict):
        # CycloneDX JSON
        if data.get("bomFormat") == "CycloneDX" or "specVersion" in data and "components" in data:
            ver = str(data.get("specVersion", "")).strip()
            if not ver:
                raise DetectionError("CycloneDX JSON missing specVersion.")
            return Detection("cyclonedx", ver, "json")
        # SPDX 2.x JSON
        if "spdxVersion" in data:
            return Detection("spdx", _normalize_spdx_version(str(data["spdxVersion"])), "json")
        # SPDX 3.x JSON-LD
        ctx = data.get("@context")
        if ctx is not None:
            blob = json.dumps(ctx) + json.dumps(data.get("@graph", ""))
            m = SPDX_CTX_VER_RE.search(blob)
            if m or "spdx" in blob.lower():
                return Detection("spdx", m.group(1) if m else "3.0.1", "json")
        # SPDX 2.x without spdxVersion but with SPDXID
        if "SPDXID" in data:
            return Detection("spdx", "2.3", "json")
    raise DetectionError("JSON document is neither CycloneDX nor SPDX.")


def detect_file(path: str, max_bytes: int = 262_144) -> Detection:
    """Detect by reading up to ``max_bytes`` (enough for the header + top-level keys)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(max_bytes)
    # For JSON we need the whole document to json.loads; re-read fully if truncated.
    if head.lstrip()[:1] in "{[" and len(head) == max_bytes:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read()
    return detect_text(head)
