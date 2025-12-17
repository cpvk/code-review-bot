"""
LLM Engine Module (Phase 3)
Manages LLM interactions for code review with smart prompting.
Supports Anthropic Claude and OpenAI GPT as providers.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod

from .models import validate_findings

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def analyze(self, prompt: str, system_prompt: str = "") -> str:
        """Send a prompt to the LLM and return the response."""
        ...

    @abstractmethod
    def analyze_structured(
        self, prompt: str, system_prompt: str = ""
    ) -> list[dict]:
        """Send a prompt and parse structured JSON response."""
        ...


class AnthropicProvider(LLMProvider):
    """Claude API provider."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5-20250929"):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def analyze(self, prompt: str, system_prompt: str = "") -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system_prompt if system_prompt else "You are an expert code reviewer.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def analyze_structured(
        self, prompt: str, system_prompt: str = ""
    ) -> list[dict]:
        full_prompt = (
            f"{prompt}\n\n"
            "Respond ONLY with a JSON array of findings. Each finding must have:\n"
            '- "line_number": int\n'
            '- "severity": "critical" | "warning" | "info"\n'
            '- "category": "security" | "bug" | "performance" | "style"\n'
            '- "issue_description": string\n'
            '- "suggested_fix": string (the corrected code)\n'
            '- "confidence": float 0-1\n'
        )
        response = self.analyze(full_prompt, system_prompt)
        return _parse_json_response(response)


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""

    def __init__(self, api_key: str, model: str = "gpt-4o"):
        import openai
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model

    def analyze(self, prompt: str, system_prompt: str = "") -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=4096,
        )
        return response.choices[0].message.content or ""

    def analyze_structured(
        self, prompt: str, system_prompt: str = ""
    ) -> list[dict]:
        full_prompt = (
            f"{prompt}\n\n"
            "Respond ONLY with a JSON array of findings. Each finding must have:\n"
            '- "line_number": int\n'
            '- "severity": "critical" | "warning" | "info"\n'
            '- "category": "security" | "bug" | "performance" | "style"\n'
            '- "issue_description": string\n'
            '- "suggested_fix": string (the corrected code)\n'
            '- "confidence": float 0-1\n'
        )
        response = self.analyze(full_prompt, system_prompt)
        return _parse_json_response(response)


def create_llm_provider(provider: str, api_key: str) -> LLMProvider:
    """Factory function to create an LLM provider.

    Args:
        provider: "anthropic" or "openai"
        api_key: API key for the provider

    Returns:
        LLMProvider instance
    """
    if provider == "anthropic":
        return AnthropicProvider(api_key=api_key)
    elif provider == "openai":
        return OpenAIProvider(api_key=api_key)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")


def _parse_json_response(response: str) -> list[dict]:
    """Extract and parse JSON array from LLM response.

    Handles cases where the LLM wraps JSON in markdown code blocks.
    """
    text = response.strip()

    # Strip markdown code block if present
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last lines (``` markers)
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return validate_findings(parsed)
        elif isinstance(parsed, dict) and "findings" in parsed:
            return validate_findings(parsed["findings"])
        return validate_findings([parsed])
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse LLM response as JSON: {text[:200]}...")
        return []
