"""
Performance Reviewer (Phase 3)
Catches: N+1 queries, unnecessary loops, memory leaks,
blocking calls in async code, inefficient data structures.

Strategy:
  1. AST pre-filter: detect nested loops, DB queries inside loops,
     high complexity functions, and repeated external calls.
  2. Build a focused prompt with complexity metrics.
  3. Call LLM to reason about algorithmic improvements.
"""

from __future__ import annotations

import logging

from ..dedup import merge_findings
from .base_reviewer import BaseReviewer

logger = logging.getLogger(__name__)


class PerformanceReviewer(BaseReviewer):
    @property
    def name(self) -> str:
        return "Performance Analysis"

    @property
    def category(self) -> str:
        return "performance"

    def review(
        self,
        code: str,
        ast_analysis: dict | None = None,
        context: dict | None = None,
    ) -> list[dict]:
        """Run performance review: AST pre-filter → LLM reasoning."""
        ast_findings = self._ast_pre_filter(code, ast_analysis)

        # Only call LLM if there are performance signals
        if not ast_findings and not self._has_performance_signals(ast_analysis):
            return []

        prompt = self._build_perf_prompt(code, ast_analysis, context, ast_findings)
        try:
            llm_findings = self.llm.analyze_structured(prompt)
        except Exception as e:
            logger.error(f"LLM call failed in performance review: {e}")
            return ast_findings

        merged = self._merge_findings(ast_findings, llm_findings)
        for f in merged:
            f["category"] = "performance"
        return merged

    # ── AST pre-filter ───────────────────────────────────────────────────────

    def _ast_pre_filter(self, code: str, ast_analysis: dict | None) -> list[dict]:
        """Detect performance patterns from AST signals."""
        if not ast_analysis:
            return []

        findings = []
        all_funcs = ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])

        for func in all_funcs:
            complexity = func.get("complexity", {})
            loops = complexity.get("loops", 0)
            nesting = complexity.get("max_nesting", 0)

            # 1. Nested loops (potential O(n^2))
            if loops >= 2 and nesting >= 2:
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "warning",
                    "category": "performance",
                    "issue_description": (
                        f"`{func['name']}` has {loops} nested loops "
                        f"(nesting depth {nesting}). "
                        "This may result in O(n^2) or worse time complexity."
                    ),
                    "suggested_fix": (
                        "Consider using sets/dicts for lookups, "
                        "or restructure to avoid nested iteration"
                    ),
                    "confidence": 0.7,
                    "source": "ast",
                })

            # 2. DB queries inside loops (N+1 query pattern)
            db_queries = func.get("db_queries", [])
            if db_queries and loops >= 1:
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "critical",
                    "category": "performance",
                    "issue_description": (
                        f"`{func['name']}` has database queries inside a loop: "
                        f"{', '.join(db_queries)}. "
                        "This is an N+1 query pattern that causes performance degradation."
                    ),
                    "suggested_fix": "Batch queries: fetch all needed data in one query before the loop",
                    "confidence": 0.85,
                    "source": "ast",
                })

            # 3. Network calls inside loops
            network_calls = func.get("network_calls", [])
            if network_calls and loops >= 1:
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "warning",
                    "category": "performance",
                    "issue_description": (
                        f"`{func['name']}` makes network calls inside a loop: "
                        f"{', '.join(network_calls)}. "
                        "Each call adds latency; consider batching."
                    ),
                    "suggested_fix": "Use async/await with asyncio.gather() or batch API requests",
                    "confidence": 0.75,
                    "source": "ast",
                })

            # 4. Very high cyclomatic complexity
            cyclomatic = complexity.get("cyclomatic", 1)
            if cyclomatic >= 15:
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "warning",
                    "category": "performance",
                    "issue_description": (
                        f"`{func['name']}` has cyclomatic complexity of {cyclomatic}. "
                        "Highly complex functions are harder to optimize and often contain "
                        "redundant computation paths."
                    ),
                    "suggested_fix": "Break into smaller functions to enable targeted optimization",
                    "confidence": 0.6,
                    "source": "ast",
                })

        return findings

    def _has_performance_signals(self, ast_analysis: dict | None) -> bool:
        """Check if AST has any signals worth sending to LLM."""
        if not ast_analysis:
            return False
        all_funcs = ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])
        for func in all_funcs:
            complexity = func.get("complexity", {})
            if complexity.get("loops", 0) >= 1:
                return True
            if func.get("db_queries") or func.get("network_calls"):
                return True
        return False

    # ── Prompt building ──────────────────────────────────────────────────────

    def _build_perf_prompt(
        self,
        code: str,
        ast_analysis: dict | None,
        context: dict | None,
        ast_findings: list[dict],
    ) -> str:
        """Build a focused performance review prompt."""
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
            # Include complexity and call patterns
            perf_summary = {
                "functions": [
                    {
                        "name": f["name"],
                        "lines": f.get("lines", ""),
                        "complexity": f.get("complexity", {}),
                        "db_queries": f.get("db_queries", []),
                        "network_calls": f.get("network_calls", []),
                        "file_operations": f.get("file_operations", []),
                        "external_calls": f.get("external_calls", []),
                    }
                    for f in ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])
                ],
            }
            parts.extend([
                "",
                "## Complexity & Call Pattern Analysis",
                "```json",
                json.dumps(perf_summary, indent=2),
                "```",
            ])

        if context and context.get("full_content"):
            parts.extend([
                "",
                "## Full File Context",
                "```python",
                context["full_content"],
                "```",
            ])

        return "\n".join(parts)

    # ── Merge findings ───────────────────────────────────────────────────────

    def _merge_findings(
        self, ast_findings: list[dict], llm_findings: list[dict]
    ) -> list[dict]:
        """Merge AST and LLM findings."""
        return merge_findings(ast_findings, llm_findings)
