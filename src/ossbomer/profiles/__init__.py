"""ossbomer.profiles — bundled public profile catalog.

A profile is a single file that binds all three layers for one regulation or
program: schema minima + conformance rules + license policy (R2), composable via
`extends` / `excludes` (R4).

Twelve profiles ship here (R3): NTIA Minimum Elements, CISA 2025 Draft Minimum,
EU CRA (Annex VII), BSI TR-03183, India CERT-In, OpenChain Telco Quality, FedRAMP
SBOM, AIBOM (net-new), and four license-policy profiles (distribution, mobile,
saas, internal).

Adopters can also keep private overlay profiles that compose public rule IDs
without vendoring the catalog (R11), via `--profile-path`.
"""
