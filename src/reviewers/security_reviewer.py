"""
Security Reviewer (Phase 3)
Catches: SQL injection, XSS, hardcoded secrets, insecure deserialization,
path traversal, command injection.

Strategy:
  1. AST pre-filter: surface security_sensitive_calls, f-strings in queries,
     global variables that look like secrets, and dangerous imports.
  2. Build a focused prompt with only the relevant signals.
  3. Call LLM to reason about data flow and exploitability.
"""

from __future__ import annotations

import logging
import re

from ..dedup import merge_findings
from .base_reviewer import BaseReviewer

logger = logging.getLogger(__name__)

# Patterns that suggest hardcoded secrets in global variables
_SECRET_PATTERNS = re.compile(
    r"(api[_-]?key|secret|password|token|credential|auth|private[_-]?key)",
    re.IGNORECASE,
)


class SecurityReviewer(BaseReviewer):
    @property
    def name(self) -> str:
        return "Security Review"

    @property
    def category(self) -> str:
        return "security"

    def review(
        self,
        code: str,
        ast_analysis: dict | None = None,
        context: dict | None = None,
    ) -> list[dict]:
        """Run security review: AST pre-filter → LLM reasoning.

        Returns list of finding dicts.
        """
        ast_findings = self._ast_pre_filter(code, ast_analysis)

        # If AST found nothing, skip LLM call to save cost
        if not ast_findings and not self._has_risky_patterns(code):
            return []

        prompt = self._build_security_prompt(code, ast_analysis, context, ast_findings)
        try:
            llm_findings = self.llm.analyze_structured(prompt)
        except Exception as e:
            logger.error(f"LLM call failed in security review: {e}")
            # Fall back to AST-only findings
            return ast_findings

        # Merge: LLM findings take priority, AST findings fill gaps
        merged = self._merge_findings(ast_findings, llm_findings)
        # Tag category
        for f in merged:
            f["category"] = "security"
        return merged

    # ── AST pre-filter ───────────────────────────────────────────────────────

    def _ast_pre_filter(self, code: str, ast_analysis: dict | None) -> list[dict]:
        """Extract security signals from AST analysis without LLM."""
        if not ast_analysis:
            return []

        findings = []

        # Check all functions for security-sensitive calls
        all_funcs = ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])
        for func in all_funcs:
            for sec_call in func.get("security_sensitive_calls", []):
                finding = self._security_call_to_finding(sec_call, func)
                if finding:
                    findings.append(finding)

        # Check for hardcoded secrets in global variables
        for var_name in ast_analysis.get("global_variables", []):
            if _SECRET_PATTERNS.search(var_name):
                findings.append({
                    "line_number": 1,
                    "severity": "critical",
                    "category": "security",
                    "issue_description": (
                        f"Potential hardcoded secret: `{var_name}`. "
                        "Secrets should be loaded from environment variables or a secrets manager."
                    ),
                    "suggested_fix": f'{var_name} = os.environ["{var_name}"]',
                    "confidence": 0.8,
                    "source": "ast",
                })

        return findings

    def _security_call_to_finding(self, sec_call: dict, func: dict) -> dict | None:
        """Convert an AST security_sensitive_call to a finding dict."""
        call_type = sec_call.get("type", "")
        call_name = sec_call.get("call", "")
        line = sec_call.get("line", 0)

        severity_map = {
            "command_injection": "critical",
            "code_execution": "critical",
            "insecure_deserialization": "critical",
            "string_interpolation_in_query": "critical",
            "dynamic_import": "warning",
            "dangerous_call": "warning",
        }

        description_map = {
            "command_injection": (
                f"`{call_name}` in `{func['name']}` — user-controlled input "
                "could lead to arbitrary command execution."
            ),
            "code_execution": (
                f"`{call_name}` in `{func['name']}` — "
                "executing dynamic code is dangerous and can lead to RCE."
            ),
            "insecure_deserialization": (
                f"`{call_name}` in `{func['name']}` — "
                "deserializing untrusted data can lead to arbitrary code execution."
            ),
            "string_interpolation_in_query": (
                f"String interpolation in `{call_name}` call in `{func['name']}` — "
                "this is vulnerable to SQL injection. Use parameterized queries."
            ),
            "dynamic_import": (
                f"`{call_name}` in `{func['name']}` — "
                "dynamic imports can execute arbitrary modules."
            ),
        }

        fix_map = {
            "command_injection": f"Use subprocess.run([...], shell=False) instead of {call_name}",
            "code_execution": f"Avoid {call_name}; use ast.literal_eval() for safe expression evaluation",
            "insecure_deserialization": "Use json.loads() or yaml.safe_load() instead",
            "string_interpolation_in_query": 'db.execute("SELECT * FROM t WHERE id = %s", (user_id,))',
        }

        return {
            "line_number": line,
            "severity": severity_map.get(call_type, "warning"),
            "category": "security",
            "issue_description": description_map.get(
                call_type,
                f"Potentially dangerous call `{call_name}` in `{func['name']}`.",
            ),
            "suggested_fix": fix_map.get(call_type, ""),
            "confidence": 0.85,
            "source": "ast",
        }

    def _has_risky_patterns(self, code: str) -> bool:
        """Quick regex check for patterns the AST might miss."""
        risky = [
            r"shell\s*=\s*True",
            r"\.format\s*\(",
            r"%\s*\(",  # old-style string formatting
            r"password\s*=\s*['\"]",
            r"secret\s*=\s*['\"]",
        ]
        return any(re.search(p, code) for p in risky)

    # ── Prompt building ──────────────────────────────────────────────────────

    def _build_security_prompt(
        self,
        code: str,
        ast_analysis: dict | None,
        context: dict | None,
        ast_findings: list[dict],
    ) -> str:
        """Build a focused security review prompt."""
        parts = [self.prompt_template]

        # Inject AST pre-filter results so LLM can validate/expand
        if ast_findings:
            parts.append("\n## AST Pre-Filter Results (validate and expand these)")
            for f in ast_findings:
                parts.append(
                    f"- Line {f['line_number']}: [{f['severity']}] {f['issue_description']}"
                )

        parts.extend(["", "## Code to Review", "```python", code, "```"])

        if ast_analysis:
            import json
            # Only include security-relevant parts to keep prompt focused
            security_summary = {
                "functions": [
                    {
                        "name": f["name"],
                        "security_sensitive_calls": f.get("security_sensitive_calls", []),
                        "external_calls": f.get("external_calls", []),
                        "db_queries": f.get("db_queries", []),
                        "network_calls": f.get("network_calls", []),
                        "file_operations": f.get("file_operations", []),
                    }
                    for f in ast_analysis.get("functions", []) + ast_analysis.get("class_methods", [])
                    if (
                        f.get("security_sensitive_calls")
                        or f.get("db_queries")
                        or f.get("network_calls")
                        or f.get("file_operations")
                    )
                ],
                "global_variables": ast_analysis.get("global_variables", []),
                "imports": ast_analysis.get("imports", []),
            }
            if security_summary["functions"] or security_summary["global_variables"]:
                parts.extend([
                    "",
                    "## Security-Relevant AST Signals",
                    "```json",
                    json.dumps(security_summary, indent=2),
                    "```",
                ])

        if context and context.get("full_content"):
            parts.extend([
                "",
                "## Full File Context (for data flow tracing)",
                "```python",
                context["full_content"],
                "```",
            ])

        return "\n".join(parts)

    # ── Merge AST + LLM findings ─────────────────────────────────────────────

    def _merge_findings(
        self, ast_findings: list[dict], llm_findings: list[dict]
    ) -> list[dict]:
        """Merge AST and LLM findings, deduplicating by line number."""
        return merge_findings(ast_findings, llm_findings)
