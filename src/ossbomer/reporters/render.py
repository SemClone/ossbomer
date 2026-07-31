"""Render results in console / JSON / SARIF (R10).

Each profile is rendered as its own independent block/run, with no aggregate line
combines scores across profiles.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from ossbomer.core.model import Category, ProfileResult, Severity, Verdict

BAR = "=" * 60


def _top_issues(result: ProfileResult, limit: int = 3) -> list[str]:
    order = {Verdict.FAIL: 0, Verdict.WARN: 1, Verdict.PASS: 2}
    sev_order = {Severity.MUST: 0, Severity.MUST_WHERE_AVAILABLE: 1,
                 Severity.SHOULD: 2, Severity.MAY: 3}
    issues = [f for f in result.findings if f.verdict is not Verdict.PASS]
    issues.sort(key=lambda f: (order[f.verdict], sev_order[f.severity]))
    out = []
    for f in issues[:limit]:
        cat = f.category.value if f.category else f.layer
        out.append(f"{cat}: {f.rule_id}: {f.message} [{f.path}]")
    return out


def render_console(sbom_path: str, results: Iterable[ProfileResult]) -> str:
    # `sbom_path` is unused here on purpose: all three renderers share one
    # signature so `render()` can dispatch without special-casing this one.
    lines: list[str] = []
    for result in results:
        lines.append(BAR)
        lines.append(f"Profile: {result.profile_name}")
        mv = result.must_violations
        suffix = f" ({mv} MUST violation{'s' if mv != 1 else ''})" if mv else ""
        lines.append(f"Verdict: {result.verdict.value}{suffix}")
        lines.append(f"Quality score: {result.score} / 100")
        for cat in [c.value for c in Category]:
            lines.append(f"  {cat + ':':<14}{result.category_scores.get(cat, 0)}")
        issues = _top_issues(result)
        if issues:
            lines.append("Top issues:")
            for i, issue in enumerate(issues, 1):
                lines.append(f"  {i}. {issue}")
    lines.append(BAR)
    return "\n".join(lines)


def render_json(sbom_path: str, results: Iterable[ProfileResult]) -> str:
    payload = {"sbom": sbom_path, "results": [r.to_dict() for r in results]}
    return json.dumps(payload, indent=2)


def _sarif_level(result_verdict: Verdict) -> str:
    # Takes the verdict alone. It previously also took a severity it never read,
    # which implied severity influenced the SARIF level; it does not, because the
    # verdict already accounts for it.
    if result_verdict is Verdict.FAIL:
        return "error"
    if result_verdict is Verdict.WARN:
        return "warning"
    return "note"


def render_sarif(sbom_path: str, results: Iterable[ProfileResult]) -> str:
    runs = []
    for result in results:
        rules: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []
        for f in result.findings:
            if f.verdict is Verdict.PASS:
                continue
            rules.setdefault(f.rule_id, {
                "id": f.rule_id,
                "properties": {"category": f.category.value if f.category else None,
                               "severity": f.severity.value},
                "shortDescription": {"text": f.citation or f.rule_id},
            })
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _sarif_level(f.verdict),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": sbom_path}},
                    "logicalLocations": [{"fullyQualifiedName": f.path or ""}],
                }],
            })
        runs.append({
            "tool": {"driver": {
                "name": f"ossbomer:{result.profile_id}",
                "informationUri": "https://github.com/SemClone/ossbomer",
                "rules": list(rules.values()),
                "properties": {"verdict": result.verdict.value, "score": result.score,
                               "categories": result.category_scores},
            }},
            "results": sarif_results,
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }, indent=2)


def render(fmt: str, sbom_path: str, results: list[ProfileResult]) -> str:
    if fmt == "json":
        return render_json(sbom_path, results)
    if fmt == "sarif":
        return render_sarif(sbom_path, results)
    return render_console(sbom_path, results)
