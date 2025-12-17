"""Typed finding schema (canonical contract for all review passes).

Reviewers historically exchanged loose dicts. This module is the single
validated schema those dicts must satisfy at pipeline boundaries
(LLM output, deduplication, comment posting). Dict in / dict out helpers
keep existing reviewer code compatible.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    BUG = "bug"
    PERFORMANCE = "performance"
    STYLE = "style"
    GENERAL = "general"


class Finding(BaseModel):
    """One review finding."""

    line_number: int = Field(default=0, ge=0)
    severity: Severity = Severity.INFO
    category: Category = Category.GENERAL
    issue_description: str = ""
    suggested_fix: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    source: str = "llm"  # "ast" | "llm"
    file: str = ""

    @field_validator("line_number", mode="before")
    @classmethod
    def _coerce_line(cls, value: object) -> object:
        # Bug reviewer historically emitted the start of a "start-end" range.
        if isinstance(value, str):
            head = value.split("-")[0].strip()
            return int(head) if head.isdigit() else 0
        return value

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls.model_validate(data)

    def to_dict(self) -> dict:
        data = self.model_dump(mode="json")
        if not data["file"]:
            data.pop("file")
        return data


def validate_findings(raw: list[dict]) -> list[dict]:
    """Validate raw (e.g. LLM) findings, dropping malformed entries."""
    valid: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            valid.append(Finding.from_dict(item).to_dict())
        except Exception:
            continue
    return valid
