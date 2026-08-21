"""Profile model and loader (R2, R4, R11).

A profile is a single YAML file binding three layers — schema minima, conformance
rules, and license policy — for one regulation or program. Profiles compose via
``extends`` (inherit rules) and ``excludes`` (drop rule ids by identity), which
also enables private overlay profiles that reference public rule IDs without
vendoring the catalog.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from dataclasses import field as dc_field
from typing import Any, ClassVar

import yaml

from .model import Category, Severity

# Bundled public catalog lives alongside this package.
CATALOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "profiles")
ENV_PATH = "OSSBOMER_PROFILE_PATH"  # os.pathsep-separated extra dirs (private overlays)


class ProfileError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    scope: str  # one of SCOPES
    severity: Severity
    category: Category | None
    validators: list[Any]  # list[str | dict]
    field: str | None = None  # IR attribute name (document/component scope)
    # Alternative IR attributes for a requirement a document may satisfy in more
    # than one way, tried in order, first one carrying a value wins. BSI
    # TR-03183-2 §5.2.4 ("CPE or purl") is the case that forced this: with a
    # single `field` the rule could only check one of the two identifiers the
    # clause accepts, so a component identified solely by CPE failed a
    # requirement it met. Empty means the single `field` above is the whole
    # lookup.
    # `dc_field`, not `field`: the attribute above shadows the dataclasses helper
    # for the rest of this class body, so the plain name is no longer callable
    # here. Renaming the attribute is not an option -- profiles name it in YAML.
    fields: list[str] = dc_field(default_factory=list)

    def lookup_fields(self) -> list[str]:
        """Every IR attribute this rule may read, in precedence order."""
        if self.fields:
            return list(self.fields)
        return [self.field] if self.field else []
    citation: str | None = None
    layer: str = "conformance"


@dataclass
class LicenseRule:
    spdx_id: str
    allowed: bool = True
    reason: str = ""


# Spec versions whose own maintainers have moved on. Applied only when a profile
# sets `deprecated_versions_forbidden`, and overridable per profile via
# `schema.deprecated_versions`, so the judgement stays data rather than a
# constant frozen into the engine.
#
# Reachability differs by format, and the difference is worth knowing. SPDX 2.0
# and 2.1 parse, so the rule genuinely decides them. CycloneDX 1.0 and 1.1 are
# rejected by cyclonedx-python-lib before any rule runs ("Unsupported
# schema_version", exit 2); they are listed anyway so the policy stays correct if
# that ever changes. CycloneDX 1.2 does parse and sits below the support matrix,
# which makes it the entry that actually bites today.
DEFAULT_DEPRECATED_VERSIONS: dict[str, list[str]] = {
    "spdx": ["2.0", "2.1"],
    "cyclonedx": ["1.0", "1.1", "1.2"],
}


@dataclass
class SchemaPolicy:
    min_versions: dict[str, str] = field(default_factory=dict)
    require_signature: bool = False
    deprecated_versions_forbidden: bool = False
    # Empty means DEFAULT_DEPRECATED_VERSIONS; a profile may narrow or widen it.
    deprecated_versions: dict[str, list[str]] = field(default_factory=dict)

    def retired_versions(self) -> dict[str, list[str]]:
        return self.deprecated_versions or DEFAULT_DEPRECATED_VERSIONS


@dataclass
class Profile:
    id: str
    name: str
    version: str = ""
    # Non-empty when the profile has been withdrawn: the reason, shown to the
    # user. A withdrawn profile must never produce a verdict. Emptying its rules
    # is not enough -- no findings computes to PASS, so a profile pulled for
    # citing a clause that does not exist would start reporting success.
    withdrawn: str = ""
    sources: list[dict[str, Any]] = field(default_factory=list)
    schema: SchemaPolicy = field(default_factory=SchemaPolicy)
    rules: list[Rule] = field(default_factory=list)
    license_use_case: str = "distribution"
    license_rules: list[LicenseRule] = field(default_factory=list)
    # "ospac" opts the license layer into policy evaluation. Empty means the
    # inline `license_rules` allow/deny list is the whole policy, which needs no
    # optional dependency.
    license_engine: str = ""
    # Directory of the adopter's own ospac policies. Resolved relative to the
    # profile file, not the working directory, so a profile stays portable.
    license_policy_path: str | None = None
    # Extra ospac match context (usage, linking_type, ...) passed through
    # unchanged, so profiles are not limited to the keys ossbomer knows about.
    license_context: dict[str, Any] = field(default_factory=dict)
    scoring_weights: dict[str, float] = field(default_factory=dict)
    scoring_thresholds: dict[str, float] = field(default_factory=dict)

    # ClassVar, not a field: without the annotation a future edit that adds one
    # would turn this into a dataclass field with a mutable default and fail at
    # class-creation time.
    DEFAULT_WEIGHTS: ClassVar[dict[str, float]] = {
        Category.COMPLETENESS.value: 0.30,
        Category.ACCURACY.value: 0.25,
        Category.CONSISTENCY.value: 0.15,
        Category.PROVENANCE.value: 0.20,
        Category.FRESHNESS.value: 0.10,
    }

    def weights(self) -> dict[str, float]:
        return self.scoring_weights or dict(self.DEFAULT_WEIGHTS)


def _search_dirs(extra: list[str] | None = None) -> list[str]:
    dirs = list(extra or [])
    if os.environ.get(ENV_PATH):
        dirs.extend(os.environ[ENV_PATH].split(os.pathsep))
    dirs.append(CATALOG_DIR)
    return dirs


def _resolve_path(name_or_path: str, extra_dirs: list[str] | None) -> str:
    if os.path.isfile(name_or_path):
        return name_or_path
    for d in _search_dirs(extra_dirs):
        for ext in (".yaml", ".yml"):
            cand = os.path.join(d, name_or_path + ext)
            if os.path.isfile(cand):
                return cand
        cand = os.path.join(d, name_or_path)
        if os.path.isfile(cand):
            return cand
    raise ProfileError(
        f"Profile not found: {name_or_path!r}. Profiles resolve by filename, so "
        f"this expects {name_or_path}.yaml in one of {_search_dirs(extra_dirs)}. "
        f"A file declaring `id: {name_or_path}` under a different name will not "
        f"be found.")


def _parse_license_rule(raw: dict[str, Any]) -> LicenseRule:
    # Overrides are matched by exact SPDX identifier. A rule carrying anything
    # else would be dropped when the override table is keyed, so it is rejected
    # here instead: a license rule that silently matches nothing, in a profile
    # with no engine, reports PASS having checked no licenses at all.
    if "expression" in raw:
        raise ProfileError(
            "license_policy rule uses 'expression', which is not supported. "
            "Overrides match a single SPDX identifier -- use 'spdx_id'. For "
            "expression-level decisions, let the engine evaluate them."
        )
    spdx_id = raw.get("spdx_id")
    if not spdx_id:
        raise ProfileError(
            f"license_policy rule is missing 'spdx_id': {raw!r}"
        )
    return LicenseRule(
        spdx_id=str(spdx_id),
        allowed=bool(raw.get("allowed", True)),
        reason=raw.get("reason", ""),
    )


# A rule naming a scope the engine does not handle silently produces no
# findings, which reads as a clean pass. `file` and `files` are one keystroke
# apart, so the typo is cheap to make and expensive to notice.
SCOPES = ("document", "component", "file", "dependency")


def _parse_rule(raw: dict[str, Any]) -> Rule:
    try:
        severity = Severity(raw["severity"])
    except (KeyError, ValueError) as exc:
        raise ProfileError(f"rule {raw.get('id')!r}: bad/missing severity") from exc
    cat_raw = raw.get("category")
    category = Category(cat_raw) if cat_raw else None
    scope = raw.get("scope", "document")
    if scope not in SCOPES:
        raise ProfileError(
            f"rule {raw.get('id')!r}: unknown scope {scope!r} "
            f"(expected one of {', '.join(SCOPES)})")
    return Rule(
        id=raw["id"],
        scope=scope,
        severity=severity,
        category=category,
        validators=raw.get("validators", []),
        field=raw.get("field"),
        fields=list(raw.get("fields", []) or []),
        citation=raw.get("citation"),
        layer=raw.get("layer", "conformance"),
    )


def _parse_document(data: dict[str, Any]) -> Profile:
    schema_raw = data.get("schema", {}) or {}
    schema = SchemaPolicy(
        min_versions=schema_raw.get("min_versions", {}) or {},
        require_signature=bool(schema_raw.get("require_signature", False)),
        deprecated_versions_forbidden=bool(
            schema_raw.get("deprecated_versions_forbidden", False)),
        deprecated_versions=schema_raw.get("deprecated_versions", {}) or {},
    )
    lic = data.get("license_policy", {}) or {}
    license_rules = [_parse_license_rule(r) for r in lic.get("rules", []) or []]
    scoring = data.get("scoring", {}) or {}
    return Profile(
        id=data["id"],
        name=data.get("name", data["id"]),
        version=str(data.get("version", "")),
        withdrawn=str(data.get("withdrawn", "") or ""),
        sources=data.get("sources", []) or [],
        schema=schema,
        rules=[_parse_rule(r) for r in data.get("rules", []) or []],
        license_use_case=lic.get("use_case", "distribution"),
        license_rules=license_rules,
        license_engine=str(lic.get("engine", "") or ""),
        license_policy_path=lic.get("policy_path"),
        license_context=lic.get("context", {}) or {},
        scoring_weights=scoring.get("weights", {}) or {},
        scoring_thresholds=scoring.get("thresholds", {}) or {},
    )


def load_profile(name_or_path: str, extra_dirs: list[str] | None = None,
                 _seen: set[str] | None = None) -> Profile:
    """Load a profile by catalog name or file path, resolving extends/excludes."""
    _seen = _seen or set()
    path = _resolve_path(name_or_path, extra_dirs)
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if "id" not in data:
        raise ProfileError(f"{path}: profile is missing an 'id'")

    # A profile has one identity spelled twice, and nothing checked the two
    # agreed. `_resolve_path` finds it by filename; every finding, report and
    # SARIF run then carries `id`. A file named `my-policy.yaml` declaring
    # `id: acme-baseline` loaded happily under `--profile my-policy` and
    # reported `acme-baseline` throughout, so grepping CI output for the name
    # that was invoked found nothing. `extends` resolves by filename while
    # `excludes` targets the id, so composition saw the split too.
    #
    # Refused rather than reconciled. Making lookup consult `id` means reading
    # every candidate file in every search directory, and turns two files
    # claiming one id into an ambiguity someone has to resolve. Every bundled
    # profile already satisfies this, so it costs the catalog nothing -- it is
    # adopters writing overlays who were paying for the split.
    stem = os.path.splitext(os.path.basename(path))[0]
    if data["id"] != stem:
        raise ProfileError(
            f"{path}: declares id {data['id']!r} but a profile is resolved by "
            f"filename, so it must be named {data['id']}.yaml -- or the id "
            f"changed to {stem!r} to match the file it is in.")

    if data["id"] in _seen:
        raise ProfileError(f"circular extends detected at {data['id']!r}")
    _seen.add(data["id"])

    profile = _parse_document(data)

    # A relative policy_path is relative to the profile that declares it, not to
    # wherever ossbomer happens to be run from -- otherwise a profile is only
    # usable from one directory.
    if profile.license_policy_path and not os.path.isabs(profile.license_policy_path):
        profile.license_policy_path = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(path)),
                         profile.license_policy_path))

    declared_license = data.get("license_policy", {}) or {}

    # Compose parents (extends) first, then layer this profile's rules on top.
    composed_rules: dict[str, Rule] = {}
    for parent in data.get("extends", []) or []:
        p = load_profile(parent, extra_dirs, _seen)
        for r in p.rules:
            composed_rules[r.id] = r
        # inherit schema minima / license policy that this profile doesn't override
        for k, v in p.schema.min_versions.items():
            profile.schema.min_versions.setdefault(k, v)
        if not profile.license_rules:
            profile.license_rules = list(p.license_rules)
        if "use_case" not in declared_license:
            profile.license_use_case = p.license_use_case
        if not profile.license_engine:
            profile.license_engine = p.license_engine
            if profile.license_policy_path is None:
                profile.license_policy_path = p.license_policy_path
        if not profile.license_context:
            profile.license_context = dict(p.license_context)
        # Scoring is inherited like everything else. Without this, a profile that
        # extends a parent and omits `scoring` silently falls back to
        # DEFAULT_WEIGHTS rather than the parent's, which reads as inheritance
        # but scores differently.
        if not profile.scoring_weights:
            profile.scoring_weights = dict(p.scoring_weights)
        if not profile.scoring_thresholds:
            profile.scoring_thresholds = dict(p.scoring_thresholds)
    for r in profile.rules:
        composed_rules[r.id] = r  # child overrides parent by id

    for excluded in data.get("excludes", []) or []:
        composed_rules.pop(excluded, None)

    profile.rules = list(composed_rules.values())
    return profile


def list_catalog(extra_dirs: list[str] | None = None) -> list[str]:
    ids: list[str] = []
    for d in _search_dirs(extra_dirs):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith((".yaml", ".yml")):
                ids.append(os.path.splitext(fn)[0])
    return sorted(set(ids))
