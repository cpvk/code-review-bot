"""Typed, validated pipeline configuration.

Single source of truth for environment-driven settings. `src.main`
keeps its legacy dict interface by delegating to `ReviewConfig`.
"""

from __future__ import annotations

import os

from pydantic import BaseModel, Field

DEFAULT_PASSES = ["security", "bug", "performance", "style"]


class ReviewConfig(BaseModel):
    github_token: str = ""
    repo: str = ""
    pr_number: int = Field(default=0, ge=0)
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    llm_provider: str = "anthropic"
    review_passes: list[str] = Field(default_factory=lambda: list(DEFAULT_PASSES))
    max_files: int = Field(default=20, gt=0)
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    @classmethod
    def from_env(cls, env: dict | None = None) -> "ReviewConfig":
        env = os.environ if env is None else env
        passes = env.get("REVIEW_PASSES", ",".join(DEFAULT_PASSES))
        return cls(
            github_token=env.get("GITHUB_TOKEN", ""),
            repo=env.get("GITHUB_REPOSITORY", ""),
            pr_number=int(env.get("PR_NUMBER", "0") or 0),
            anthropic_api_key=env.get("ANTHROPIC_API_KEY", ""),
            openai_api_key=env.get("OPENAI_API_KEY", ""),
            llm_provider=env.get("LLM_PROVIDER", "anthropic"),
            review_passes=[p.strip() for p in passes.split(",") if p.strip()],
            max_files=int(env.get("MAX_FILES", "20") or 20),
            confidence_threshold=float(env.get("CONFIDENCE_THRESHOLD", "0.5") or 0.5),
        )

    def api_key_for_provider(self) -> str:
        return self.anthropic_api_key if self.llm_provider == "anthropic" else self.openai_api_key

    def to_legacy_dict(self) -> dict:
        return self.model_dump()
