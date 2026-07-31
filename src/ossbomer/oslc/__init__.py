"""License policy — evaluated by `ospac` (Open Source Policy as Code).

Declared licenses from the SBOM are judged against an ospac policy for the use
case a profile names (distribution, mobile, saas, internal). The policy rules
live in ospac, so adopters change the answer by pointing a profile at their own
policy directory rather than by changing this package. See
:mod:`ossbomer.oslc.policy`.

Package/PURL risk is a separate, still-pending concern: the 136 MB bundled OSSA
advisory dataset and the former `PackageRiskAnalyzer` were removed, and risk will
be served by the forthcoming open PURL API as an opt-in network feature.
"""
