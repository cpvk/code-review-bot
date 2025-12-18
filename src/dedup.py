"""Finding deduplication and AST/LLM merge helpers.

Canonical implementation of the logic previously copied into
`src.main` and every reviewer. Key: (file, line, category) for
cross-pass dedup; plain line number for a single pass's AST+LLM merge.
"""

from __future__ import annotations


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Keep the highest-confidence finding per (file, line, category)."""
    seen: dict[tuple, dict] = {}
    for finding in findings:
        key = (
            finding.get("file", ""),
            int(finding.get("line_number", 0) or 0),
            finding.get("category", ""),
        )
        existing = seen.get(key)
        if existing is None or finding.get("confidence", 0) > existing.get("confidence", 0):
            seen[key] = finding
    return list(seen.values())


def merge_findings(ast_findings: list[dict], llm_findings: list[dict]) -> list[dict]:
    """Merge one pass's AST + LLM findings by line; LLM wins ties."""
    merged: dict[int, dict] = {}
    for finding in ast_findings:
        merged[int(finding.get("line_number", 0) or 0)] = finding
    for finding in llm_findings:
        key = int(finding.get("line_number", 0) or 0)
        existing = merged.get(key)
        if existing is None or finding.get("confidence", 0) >= existing.get("confidence", 0):
            finding = {**finding, "source": "llm"}
            merged[key] = finding
    return list(merged.values())
