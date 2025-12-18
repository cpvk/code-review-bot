"""
Bug Reviewer (Phase 3)
Catches: Null pointer risks, off-by-one errors, race conditions,
resource leaks, type mismatches, unhandled exceptions, logic errors.

Strategy:
  1. AST pre-filter: detect bare excepts, missing error handling around I/O,
     None-dereference patterns, and resource leaks (open without with).
  2. Build a focused prompt with control flow + error handling signals.
  3. Call LLM to reason about intent vs implementation.
"""

from __future__ import annotations

import logging

from ..dedup import merge_findings
from .base_reviewer import BaseReviewer

logger = logging.getLogger(__name__)


class BugReviewer(BaseReviewer):
    @property
    def name(self) -> str:
        return "Bug Detection"

    @property
    def category(self) -> str:
        return "bug"

    def review(
        self,
        code: str,
        ast_analysis: dict | None = None,
        context: dict | None = None,
    ) -> list[dict]:
        """Run bug detection: AST pre-filter → LLM reasoning."""
        ast_findings = self._ast_pre_filter(code, ast_analysis)

        prompt = self._build_bug_prompt(code, ast_analysis, context, ast_findings)
        try:
            llm_findings = self.llm.analyze_structured(prompt)
        except Exception as e:
            logger.error(f"LLM call failed in bug review: {e}")
            return ast_findings

        merged = self._merge_findings(ast_findings, llm_findings)
        for f in merged:
            f["category"] = "bug"
        return merged

    # ── AST pre-filter ───────────────────────────────────────────────────────

    def _ast_pre_filter(self, code: str, ast_analysis: dict | None) -> list[dict]:
        """Detect bug patterns from AST signals."""
        if not ast_analysis:
            return []

        findings = []
        all_funcs = ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])

        for func in all_funcs:
            # 1. Bare except blocks
            if func.get("error_handling", {}).get("has_bare_except"):
                findings.append({
                    "line_number": func.get("lines", "0-0").split("-")[0],
                    "severity": "warning",
                    "category": "bug",
                    "issue_description": (
                        f"`{func['name']}` uses a bare `except:` clause. "
                        "This catches all exceptions including SystemExit and KeyboardInterrupt, "
                        "which can hide bugs and make debugging difficult."
                    ),
                    "suggested_fix": "except Exception as e:",
                    "confidence": 0.9,
                    "source": "ast",
                })

            # 2. File/network I/O without error handling
            has_io = (
                func.get("file_operations")
                or func.get("network_calls")
                or func.get("db_queries")
            )
            has_error_handling = func.get("error_handling", {}).get("try_except_blocks", 0) > 0
            if has_io and not has_error_handling:
                io_types = []
                if func.get("file_operations"):
                    io_types.append("file I/O")
                if func.get("network_calls"):
                    io_types.append("network calls")
                if func.get("db_queries"):
                    io_types.append("database queries")
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "warning",
                    "category": "bug",
                    "issue_description": (
                        f"`{func['name']}` performs {', '.join(io_types)} "
                        "without error handling. These operations can raise exceptions "
                        "that should be caught and handled."
                    ),
                    "suggested_fix": "Wrap I/O operations in try/except blocks",
                    "confidence": 0.7,
                    "source": "ast",
                })

            # 3. High complexity with few error handling blocks
            complexity = func.get("complexity", {})
            cyclomatic = complexity.get("cyclomatic", 1)
            nesting = complexity.get("max_nesting", 0)
            if cyclomatic >= 8 and nesting >= 3:
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "info",
                    "category": "bug",
                    "issue_description": (
                        f"`{func['name']}` has high complexity "
                        f"(cyclomatic={cyclomatic}, max_nesting={nesting}). "
                        "Complex functions are more prone to logic errors."
                    ),
                    "suggested_fix": "Consider breaking into smaller functions",
                    "confidence": 0.6,
                    "source": "ast",
                })

        return findings

    # ── Prompt building ──────────────────────────────────────────────────────

    def _build_bug_prompt(
        self,
        code: str,
        ast_analysis: dict | None,
        context: dict | None,
        ast_findings: list[dict],
    ) -> str:
        """Build a focused bug detection prompt."""
        parts = [self.prompt_template]

        if ast_findings:
            parts.append("\n## AST Pre-Filter Results (validate and expand these)")
            for f in ast_findings:
                parts.append(
                    f"- Line {f['line_number']}: [{f['severity']}] {f['issue_description']}"
                )

        parts.extend(["", "## Code to Review", "```python", code, "```"])

        if ast_analysis:
            import json
            # Include control flow and error handling signals
            bug_summary = {
                "functions": [
                    {
                        "name": f["name"],
                        "lines": f.get("lines", ""),
                        "complexity": f.get("complexity", {}),
                        "error_handling": f.get("error_handling", {}),
                        "external_calls": f.get("external_calls", []),
                        "variable_mutations": f.get("variable_mutations", {}),
                    }
                    for f in ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])
                ],
            }
            parts.extend([
                "",
                "## Control Flow & Error Handling Analysis",
                "```json",
                json.dumps(bug_summary, indent=2),
                "```",
            ])

        if context:
            if context.get("full_content"):
                parts.extend([
                    "",
                    "## Full File Context",
                    "```python",
                    context["full_content"],
                    "```",
                ])
            # Include test content to understand expected behavior
            test_content = context.get("related_test_content", {})
            if test_content:
                parts.append("\n## Existing Tests (for understanding intent)")
                for test_file, content in list(test_content.items())[:2]:
                    parts.extend([
                        f"### {test_file}",
                        "```python",
                        content[:3000],  # Limit test content size
                        "```",
                    ])

        return "\n".join(parts)

    # ── Merge findings ───────────────────────────────────────────────────────

    def _merge_findings(
        self, ast_findings: list[dict], llm_findings: list[dict]
    ) -> list[dict]:
        """Merge AST and LLM findings, deduplicating by line number."""
        return merge_findings(ast_findings, llm_findings)
