"""OSSBomer: SBOM validation, conformance, and license-policy checks driven by regulatory profiles.

A single tool with three layers over a shared core:

    - ossbomer.schema        structural validation (SPDX / CycloneDX)
    - ossbomer.conformance   field/content rules against regulations and programs
    - ossbomer.oslc          license policy, evaluated by `ospac`

All three are evaluated by the one profile engine in `ossbomer.core`; the
per-layer modules are the backward-compatible command surface (N4).

Extensibility has two axes:
    - profiles (data): new regulations / company requirements are YAML, no code
    - plugins  (code): new BOM types (aiBOM, eBOM, cBOM, ...) ship as optional libs
"""

__version__ = "2.2.1"
