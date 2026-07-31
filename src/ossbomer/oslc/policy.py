"""License policy evaluation backed by `ospac` (Open Source Policy as Code).

The OSLC layer answers one question per declared license: given a use case --
distribution, mobile, saas, internal -- does policy allow it? The rules live in
ospac rather than here, so an organization can point a profile at its own policy
directory and change the answer without changing ossbomer.

ospac is an optional dependency (``pip install "ossbomer[oslc]"``). A profile
that asks for it and cannot get it fails loudly: silently skipping the license
layer would report a clean verdict for a document nobody license-checked.

Everything here is offline (N2). ospac ships its default policy and its license
data inside the package.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ospac's PolicyResult.aggregate() replaces the matched rule's message with a
# count. That is bookkeeping, not something to show a user next to a failed
# component, so it is dropped and the caller phrases its own. Matching the shape
# rather than overriding unconditionally means a future ospac that aggregates
# messages properly starts coming through on its own.
_AGGREGATE_PLACEHOLDER = re.compile(r"^Evaluated \d+ rules?$")

# ospac action names ordered by how restrictive they are. Mirrors the ordering
# ospac itself uses when aggregating rule results.
_RESTRICTIVENESS = {
    "approve": 1,
    "allow": 2,
    "flag_for_review": 3,
    "contaminate": 4,
    "deny": 5,
}

DENYING_ACTIONS = frozenset({"deny", "contaminate"})


class OspacUnavailable(RuntimeError):
    """A profile needs the ospac policy engine and it is not installed."""


@dataclass
class LicenseDecision:
    """What policy says about one declared license."""

    license: str
    action: str = "allow"
    severity: str = "info"
    message: str = ""
    remediation: str = ""
    requirements: list[str] = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return self.action in DENYING_ACTIONS

    @property
    def needs_review(self) -> bool:
        return self.action == "flag_for_review"

    def _rank(self) -> int:
        return _RESTRICTIVENESS.get(self.action, 0)


def _import_runtime() -> Any:
    try:
        from ospac import PolicyRuntime
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise OspacUnavailable(
            "this profile declares an ospac license policy, but the ospac "
            'policy engine is not installed. Install it with: pip install "ossbomer[oslc]"'
        ) from exc
    return PolicyRuntime


class LicensePolicy:
    """Evaluates declared licenses against an ospac policy for one use case.

    ``use_case`` is passed to ospac as ``distribution_type``, which is the key
    its shipped policy matches on (commercial, embedded, saas, mobile, desktop,
    web, cloud, api). Anything else a policy wants to match -- ``usage``,
    ``linking_type`` -- comes through ``context`` unchanged, so profiles are not
    limited to the vocabulary this module happens to know about.
    """

    def __init__(self, use_case: str = "distribution",
                 policy_path: str | None = None,
                 context: dict[str, Any] | None = None) -> None:
        runtime_cls = _import_runtime()
        self.use_case = use_case
        self.policy_path = policy_path
        self.context = dict(context or {})
        self._runtime = runtime_cls(policy_path) if policy_path else runtime_cls()
        self._cache: dict[str, LicenseDecision] = {}

    # -- license metadata ------------------------------------------------------

    def _license_type(self, license_id: str) -> str | None:
        """ospac's classification for a license: permissive, copyleft_strong, ..."""
        try:
            data = self._runtime.lookup_license_data(license_id)
        # lookup_license_data validates the id and raises on anything that is not
        # a bare SPDX identifier. An unrecognized id is not an error here -- it
        # simply has no classification, and policy can still match on the id.
        except Exception:  # noqa: BLE001
            return None
        if not data:
            return None
        return (data.get("license") or {}).get("type")

    # -- single identifier -----------------------------------------------------

    def _decide_identifier(self, license_id: str) -> LicenseDecision:
        lic_type = self._license_type(license_id)
        context: dict[str, Any] = {
            "license": license_id,
            "licenses": [license_id],
            "distribution_type": self.use_case,
        }
        if lic_type:
            # ospac policies match on either spelling.
            context["license_type"] = lic_type
            context["license_category"] = lic_type
        else:
            context["license_type"] = "unknown"
        context.update(self.context)

        result = self._runtime.evaluate(context)
        action = getattr(result.action, "value", result.action)
        message = result.message or ""
        if _AGGREGATE_PLACEHOLDER.match(message.strip()):
            message = ""
        return LicenseDecision(
            license=license_id,
            action=str(action),
            severity=result.severity or "info",
            message=message,
            remediation=result.remediation or "",
            requirements=list(result.requirements or []),
        )

    # -- expressions -----------------------------------------------------------

    def decide(self, expression: str) -> LicenseDecision:
        """Decide a declared license, which may be an SPDX expression.

        Expression semantics matter for correctness, not just tidiness:

        * ``A OR B`` -- the licensee chooses, so the *least* restrictive operand
          governs. Denying ``MIT OR GPL-3.0-only`` because of the GPL operand
          would be simply wrong.
        * ``A AND B`` -- every operand applies, so the *most* restrictive governs.
        """
        cached = self._cache.get(expression)
        if cached is not None:
            return cached

        decision = self._decide_expression(expression)
        # Report against what the document actually declared.
        decision.license = expression
        self._cache[expression] = decision
        return decision

    def _decide_expression(self, expression: str) -> LicenseDecision:
        try:
            from license_expression import AND, OR, get_spdx_licensing
        except ImportError:  # pragma: no cover - present via the SBOM parsers
            return self._decide_identifier(expression)

        try:
            parsed = get_spdx_licensing().parse(expression)
        # An unparseable expression is still worth asking policy about verbatim:
        # a policy may list the exact string, and "unknown" is a reviewable answer.
        except Exception:  # noqa: BLE001
            return self._decide_identifier(expression)

        if parsed is None:
            return self._decide_identifier(expression)

        return self._walk(parsed, OR, AND)

    def _walk(self, node: Any, or_cls: type, and_cls: type) -> LicenseDecision:
        args = getattr(node, "args", ()) or ()
        if not args:
            # A bare symbol, or "X WITH Y". Classify on the base license, since
            # ospac's data is keyed by license id, not by id-plus-exception.
            base = getattr(node, "license_symbol", None)
            return self._decide_identifier(str(base) if base is not None else str(node))

        decisions = [self._walk(a, or_cls, and_cls) for a in args]
        if isinstance(node, or_cls):
            return min(decisions, key=LicenseDecision._rank)
        if isinstance(node, and_cls):
            return max(decisions, key=LicenseDecision._rank)
        # Any other node shape: be conservative rather than optimistic.
        return max(decisions, key=LicenseDecision._rank)
