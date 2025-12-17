"""
Comment Formatter Module (Phase 3)
Formats review findings into clean, actionable GitHub PR review comments
with severity badges, explanations, fix suggestions, and confidence scores.
"""

from __future__ import annotations


SEVERITY_BADGES = {
    "critical": "🔴 **Critical**",
    "warning": "🟡 **Warning**",
    "info": "🔵 **Info**",
}

CATEGORY_LABELS = {
    "security": "Security",
    "bug": "Bug",
    "performance": "Performance",
    "style": "Style & Design",
}


def format_review_comment(finding: dict) -> str:
    """Format a single finding into a GitHub review comment.

    Args:
        finding: Dict with keys: severity, category, issue_description,
                 suggested_fix, confidence

    Returns:
        Formatted markdown string for the comment body.
    """
    severity = finding.get("severity", "info")
    category = finding.get("category", "general")
    description = finding.get("issue_description", "")
    suggested_fix = finding.get("suggested_fix", "")
    confidence = finding.get("confidence", 0.0)

    badge = SEVERITY_BADGES.get(severity, SEVERITY_BADGES["info"])
    cat_label = CATEGORY_LABELS.get(category, category.title())

    parts = [
        f"{badge} [{cat_label}] — Confidence: {confidence:.0%}",
        "",
        description,
    ]

    if suggested_fix:
        parts.extend([
            "",
            "**Suggested fix:**",
            "```suggestion",
            suggested_fix,
            "```",
        ])

    return "\n".join(parts)


def format_review_summary(findings: list[dict], files_reviewed: int) -> str:
    """Format an overall review summary.

    Args:
        findings: List of all findings.
        files_reviewed: Number of files reviewed.

    Returns:
        Formatted markdown summary string.
    """
    if not findings:
        return (
            "## AI Code Review\n\n"
            f"Reviewed **{files_reviewed}** files — no issues found. ✅"
        )

    by_severity = {}
    by_category = {}
    for f in findings:
        sev = f.get("severity", "info")
        cat = f.get("category", "general")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1

    lines = [
        "## AI Code Review Summary",
        "",
        f"Reviewed **{files_reviewed}** files and found **{len(findings)}** issues:",
        "",
    ]

    for sev in ["critical", "warning", "info"]:
        count = by_severity.get(sev, 0)
        badge = SEVERITY_BADGES.get(sev, "")
        lines.append(f"- {badge}: {count}")

    lines.extend(["", "**By category:**", ""])
    for cat, count in sorted(by_category.items()):
        label = CATEGORY_LABELS.get(cat, cat.title())
        lines.append(f"- {label}: {count}")

    lines.extend([
        "",
        "---",
        "_Review powered by AI Code Reviewer — AST analysis + multi-pass LLM reasoning_",
    ])

    return "\n".join(lines)
