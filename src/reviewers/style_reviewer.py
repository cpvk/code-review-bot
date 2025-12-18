"""
Style & Design Reviewer (Phase 3)
Catches: Code duplication, poor naming, missing error handling,
SOLID violations, magic numbers, missing type hints, complex functions.

Strategy:
  1. AST pre-filter: detect functions missing type hints, high complexity,
     many parameters, and missing docstrings.
  2. Build a focused prompt with structural analysis.
  3. Call LLM to compare against repo conventions and suggest improvements.
"""

from __future__ import annotations

import logging

from .base_reviewer import BaseReviewer

logger = logging.getLogger(__name__)

# Thresholds
MAX_PARAMS = 5
MAX_COMPLEXITY = 10
MAX_FUNCTION_LINES = 50


class StyleReviewer(BaseReviewer):
    @property
    def name(self) -> str:
        return "Style & Design"

    @property
    def category(self) -> str:
        return "style"

    def review(
        self,
        code: str,
        ast_analysis: dict | None = None,
        context: dict | None = None,
    ) -> list[dict]:
        """Run style review: AST pre-filter → LLM reasoning."""
        ast_findings = self._ast_pre_filter(code, ast_analysis)

        prompt = self._build_style_prompt(code, ast_analysis, context, ast_findings)
        try:
            llm_findings = self.llm.analyze_structured(prompt)
        except Exception as e:
            logger.error(f"LLM call failed in style review: {e}")
            return ast_findings

        merged = self._merge_findings(ast_findings, llm_findings)
        for f in merged:
            f["category"] = "style"
        return merged

    # ── AST pre-filter ───────────────────────────────────────────────────────

    def _ast_pre_filter(self, code: str, ast_analysis: dict | None) -> list[dict]:
        """Detect style/design patterns from AST signals."""
        if not ast_analysis:
            return []

        findings = []
        all_funcs = ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])

        for func in all_funcs:
            # 1. Too many parameters
            params = func.get("parameters", [])
            if len(params) > MAX_PARAMS:
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "info",
                    "category": "style",
                    "issue_description": (
                        f"`{func['name']}` has {len(params)} parameters "
                        f"(threshold: {MAX_PARAMS}). "
                        "Too many parameters suggest the function is doing too much."
                    ),
                    "suggested_fix": "Group related parameters into a dataclass or config object",
                    "confidence": 0.7,
                    "source": "ast",
                })

            # 2. High cyclomatic complexity
            complexity = func.get("complexity", {})
            cyclomatic = complexity.get("cyclomatic", 1)
            if cyclomatic > MAX_COMPLEXITY:
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "warning",
                    "category": "style",
                    "issue_description": (
                        f"`{func['name']}` has cyclomatic complexity of {cyclomatic} "
                        f"(threshold: {MAX_COMPLEXITY}). "
                        "Consider refactoring into smaller functions."
                    ),
                    "suggested_fix": "Extract conditional branches into helper functions",
                    "confidence": 0.8,
                    "source": "ast",
                })

            # 3. Long functions
            lines_str = func.get("lines", "0-0")
            parts = lines_str.split("-")
            start = int(parts[0])
            end = int(parts[1]) if len(parts) > 1 else start
            func_length = end - start + 1
            if func_length > MAX_FUNCTION_LINES:
                findings.append({
                    "line_number": start,
                    "severity": "info",
                    "category": "style",
                    "issue_description": (
                        f"`{func['name']}` is {func_length} lines long "
                        f"(threshold: {MAX_FUNCTION_LINES}). "
                        "Long functions are harder to understand and test."
                    ),
                    "suggested_fix": "Break into smaller, focused functions",
                    "confidence": 0.65,
                    "source": "ast",
                })

            # 4. Missing return type annotation
            if func.get("return_type") is None and not func["name"].startswith("_"):
                findings.append({
                    "line_number": int(func.get("lines", "0-0").split("-")[0]),
                    "severity": "info",
                    "category": "style",
                    "issue_description": (
                        f"Public function `{func['name']}` is missing a return type annotation."
                    ),
                    "suggested_fix": f"def {func['name']}(...) -> ReturnType:",
                    "confidence": 0.6,
                    "source": "ast",
                })

        return findings

    # ── Prompt building ──────────────────────────────────────────────────────

    def _build_style_prompt(
        self,
        code: str,
        ast_analysis: dict | None,
        context: dict | None,
        ast_findings: list[dict],
    ) -> str:
        """Build a focused style review prompt."""
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
            # Include structural analysis for style review
            style_summary = {
                "functions": [
                    {
                        "name": f["name"],
                        "lines": f.get("lines", ""),
                        "parameters": f.get("parameters", []),
                        "return_type": f.get("return_type"),
                        "decorators": f.get("decorators", []),
                        "complexity": f.get("complexity", {}),
                    }
                    for f in ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])
                ],
                "classes": ast_analysis.get("classes", []),
                "total_lines": ast_analysis.get("total_lines", 0),
            }
            parts.extend([
                "",
                "## Structural Analysis",
                "```json",
                json.dumps(style_summary, indent=2),
                "```",
            ])

        # Include context for convention comparison
        if context:
            if context.get("imported_module_signatures"):
                parts.append("\n## Imported Module Signatures (for convention reference)")
                for module, sigs in context["imported_module_signatures"].items():
                    parts.append(f"### {module}")
                    for sig in sigs:
                        parts.append(f"  - {sig}")

        return "\n".join(parts)

    # ── Merge findings ───────────────────────────────────────────────────────

    def _merge_findings(
        self, ast_findings: list[dict], llm_findings: list[dict]
    ) -> list[dict]:
        """Merge AST and LLM findings."""
        merged = {}

        for f in ast_findings:
            key = (int(f.get("line_number", 0)), f.get("issue_description", "")[:50])
            merged[key] = f

        for f in llm_findings:
            key = (int(f.get("line_number", 0)), f.get("issue_description", "")[:50])
            if key not in merged:
                f["source"] = "llm"
                merged[key] = f
            else:
                existing = merged[key]
                if f.get("confidence", 0) >= existing.get("confidence", 0):
                    f["source"] = "llm"
                    merged[key] = f

        return list(merged.values())
