"""
Base Reviewer (Phase 3)
Abstract base class for all review passes.
Each reviewer implements a specialized analysis strategy.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseReviewer(ABC):
    """Abstract base class for review passes."""

    def __init__(self, llm_provider, prompt_template: str = ""):
        self.llm = llm_provider
        self.prompt_template = prompt_template

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this review pass."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Category tag: security, bug, performance, or style."""
        ...

    @abstractmethod
    def review(
        self,
        code: str,
        ast_analysis: dict | None = None,
        context: dict | None = None,
    ) -> list[dict]:
        """Run this review pass on a piece of code.

        Args:
            code: The source code to review.
            ast_analysis: Structured AST analysis (from ast_analyzer).
            context: Related files and context (from context_gatherer).

        Returns:
            List of finding dicts with: line_number, severity, category,
            issue_description, suggested_fix, confidence.
        """
        ...

    def _build_prompt(self, code: str, ast_analysis: dict | None, context: dict | None) -> str:
        """Build the prompt to send to the LLM."""
        parts = [self.prompt_template, "", "## Code to Review", "```python", code, "```"]

        if ast_analysis:
            import json
            parts.extend(["", "## AST Analysis", "```json", json.dumps(ast_analysis, indent=2), "```"])

        if context and context.get("full_content"):
            parts.extend(["", "## Full File Context", "```python", context["full_content"], "```"])

        return "\n".join(parts)
