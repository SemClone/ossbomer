"""Shared value types for the rule engine, scoring, and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    MUST = "MUST"
    MUST_WHERE_AVAILABLE = "MUST_WHERE_AVAILABLE"
    SHOULD = "SHOULD"
    MAY = "MAY"


class Verdict(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class Category(str, Enum):
    COMPLETENESS = "Completeness"
    ACCURACY = "Accuracy"
    CONSISTENCY = "Consistency"
    PROVENANCE = "Provenance"
    FRESHNESS = "Freshness"


@dataclass
class Finding:
    """One rule outcome against one target (document / component / dependency)."""

    rule_id: str
    layer: str  # "schema" | "conformance" | "oslc"
    severity: Severity
    category: Category | None
    verdict: Verdict
    citation: str | None = None
    # e.g. "components[42].version" or "document.creators"
    path: str | None = None
    value: Any = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "layer": self.layer,
            "severity": self.severity.value,
            "category": self.category.value if self.category else None,
            "verdict": self.verdict.value,
            "citation": self.citation,
            "path": self.path,
            "message": self.message,
        }


@dataclass
class ProfileResult:
    """The independent result for a single profile (never blended with others)."""

    profile_id: str
    profile_name: str
    verdict: Verdict
    score: int
    category_scores: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    # schema gate result summary
    schema_valid: bool | None = None
    # The standard(s) the profile encodes, carried through from the profile file.
    # A compliance report should say what it is claiming compliance *with*.
    sources: list[dict[str, Any]] = field(default_factory=list)

    @property
    def must_violations(self) -> int:
        return sum(1 for f in self.findings
                   if f.verdict is Verdict.FAIL and f.severity is Severity.MUST)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile_id,
            "name": self.profile_name,
            "verdict": self.verdict.value,
            "score": self.score,
            "schema_valid": self.schema_valid,
            "sources": self.sources,
            "categories": self.category_scores,
            "findings": [f.to_dict() for f in self.findings],
        }
