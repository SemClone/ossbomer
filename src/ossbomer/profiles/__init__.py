"""ossbomer.profiles — bundled public profile catalog.

A profile is a single file that binds all three layers for one regulation or
program: schema minima + conformance rules + license policy (R2), composable via
`extends` / `excludes` (R4).

Fourteen usable profiles ship here (R3): CISA 2026 Minimum Elements, NTIA Minimum
Elements (2021, superseded), CISA 2025 Draft Minimum (superseded), EU CRA
(Annex I Part II(1)), BSI TR-03183, India CERT-In, OpenChain Telco Quality,
FedRAMP SBOM, OMB M-26-05, AIBOM (net-new), and four license-policy profiles
(distribution, mobile, saas, internal).

Adopters can also keep private overlay profiles that compose public rule IDs
without vendoring the catalog (R11), via `--profile-path`.
"""
