"""ossbomer.core — the shared foundation every layer runs on.

Responsibilities (requirements R2, R4, R7, R8; N3):
    - Canonical SBOM intermediate representation (IR) that iterates per component
      AND per dependency, not only top-level metadata (R8).
    - SPDX / CycloneDX parsers built on mature libraries (spdx-tools,
      cyclonedx-python-lib) rather than hand-rolled XML (N3).
    - YAML profile loader with `extends` / `excludes` composition (R2, R4).
    - Rule engine + pluggable validator registry, plus a Python plugin escape
      hatch for extension libs / new BOM types such as aiBOM, eBOM, cBOM (R7).
    - Severity model: MUST / MUST_WHERE_AVAILABLE / SHOULD / MAY (R5), with each
      rule citing its regulatory source (R6).

The schema / conformance / oslc layers are re-based onto this core: they preselect
profiles over the one engine here and carry no parsing logic of their own.
"""
