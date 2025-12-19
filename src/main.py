"""
Main Entry Point
Receives PR events and orchestrates the full review pipeline:
  1. Parse PR diff
  2. Gather context (related files, imports, tests)
  3. Run AST analysis on changed Python files
  4. Execute multi-pass review (Security, Bugs, Performance, Style)
  5. Deduplicate and format findings
  6. Post review comments on the PR
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time

from .ast_analyzer import FileAnalysis, analyze_python_file
from .config import ReviewConfig
from .context_gatherer import FileContext, gather_context
from .dedup import deduplicate_findings
from .diff_parser import PRDiff, parse_github_pr_files
from .github_client import GitHubClient, ReviewComment, format_finding_as_comment
from .llm_engine import create_llm_provider
from .reviewers.bug_reviewer import BugReviewer
from .reviewers.performance_reviewer import PerformanceReviewer
from .reviewers.security_reviewer import SecurityReviewer
from .reviewers.style_reviewer import StyleReviewer

logger = logging.getLogger(__name__)


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def get_config_from_env() -> dict:
    """Read configuration from environment variables (set by GitHub Actions)."""
    return ReviewConfig.from_env().to_legacy_dict()


def run_review(config: dict) -> dict:
    """Run the full review pipeline.

    Args:
        config: Configuration dict with GitHub token, repo, PR number, etc.

    Returns:
        Dict with review results summary.
    """
    start_time = time.time()

    # Step 1: Fetch PR data
    logger.info(f"Fetching PR #{config['pr_number']} from {config['repo']}")
    github_client = GitHubClient(token=config["github_token"])

    try:
        pr_metadata = github_client.get_pr_metadata(config["repo"], config["pr_number"])
        logger.info(f"PR: {pr_metadata['title']} by {pr_metadata['author']}")

        pr_files = github_client.get_pr_files(config["repo"], config["pr_number"])
        logger.info(f"Found {len(pr_files)} changed files")

        # Step 2: Parse the diff
        pr_diff = parse_github_pr_files(pr_files)
        python_files = pr_diff.python_files

        if not python_files:
            logger.info("No Python files changed. Skipping review.")
            return {"status": "skipped", "reason": "no_python_files", "findings": []}

        logger.info(
            f"Reviewing {len(python_files)} Python files "
            f"({pr_diff.total_additions} additions, {pr_diff.total_deletions} deletions)"
        )

        # Apply max files limit
        if len(python_files) > config["max_files"]:
            logger.warning(
                f"PR has {len(python_files)} Python files, limiting to {config['max_files']}"
            )
            python_files = python_files[: config["max_files"]]

        # Step 3: Gather context for each file (imports, tests, related code)
        contexts = _gather_context(github_client, config, python_files, pr_metadata)

        # Step 4: Run AST analysis on each file (tree-sitter)
        ast_results = _run_ast_analysis(config, python_files, contexts)

        # Step 5: Run multi-pass review (Phase 3)
        findings = _run_review_passes(config, python_files, contexts, ast_results)

        # Step 6: Filter by confidence threshold
        filtered_findings = [
            f for f in findings if f.get("confidence", 0) >= config["confidence_threshold"]
        ]
        logger.info(
            f"Found {len(findings)} issues, {len(filtered_findings)} above confidence threshold"
        )

        # Step 7: Post review comments
        if filtered_findings:
            _post_review(github_client, config, pr_diff, filtered_findings, pr_metadata)

        elapsed = time.time() - start_time
        logger.info(f"Review completed in {elapsed:.1f}s")

        return {
            "status": "completed",
            "files_reviewed": len(python_files),
            "functions_analyzed": sum(
                len(a.all_functions) for a in ast_results.values()
            ),
            "security_concerns": sum(
                1 for a in ast_results.values() if a.has_security_concerns
            ),
            "total_findings": len(findings),
            "posted_findings": len(filtered_findings),
            "elapsed_seconds": round(elapsed, 1),
        }

    finally:
        github_client.close()


def _gather_context(
    github_client: GitHubClient,
    config: dict,
    python_files: list,
    pr_metadata: dict,
) -> dict[str, FileContext]:
    """Gather context for each changed file (imports, related files, tests)."""
    contexts = {}
    head_sha = pr_metadata.get("head_sha")

    for file in python_files:
        try:
            ctx = gather_context(
                github_client,
                config["repo"],
                file.filename,
                ref=head_sha,
            )
            contexts[file.filename] = ctx
            logger.info(
                f"Context for {file.filename}: "
                f"{len(ctx.imports)} imports, "
                f"{len(ctx.related_test_files)} test files"
            )
        except Exception as e:
            logger.warning(f"Failed to gather context for {file.filename}: {e}")
            contexts[file.filename] = FileContext(filename=file.filename)

    return contexts


def _run_ast_analysis(
    config: dict,
    python_files: list,
    contexts: dict[str, FileContext],
) -> dict[str, FileAnalysis]:
    """Run AST analysis on each changed Python file.

    Uses the full file content from context (not just the diff) to build
    complete AST, then focuses analysis on changed functions.
    """
    results = {}

    for file in python_files:
        ctx = contexts.get(file.filename)
        source = ctx.full_content if ctx else None

        if not source:
            logger.warning(f"No source content for {file.filename}, skipping AST analysis")
            continue

        try:
            file_analysis = analyze_python_file(source, file.filename)
            results[file.filename] = file_analysis

            # Log summary
            func_count = len(file_analysis.all_functions)
            security_count = sum(
                len(f.security_sensitive_calls) for f in file_analysis.all_functions
            )
            logger.info(
                f"AST analysis for {file.filename}: "
                f"{func_count} functions, "
                f"{security_count} security-sensitive calls, "
                f"security_concerns={file_analysis.has_security_concerns}"
            )
        except Exception as e:
            logger.warning(f"AST analysis failed for {file.filename}: {e}")

    return results


def _run_review_passes(
    config: dict,
    python_files: list,
    contexts: dict[str, FileContext],
    ast_results: dict[str, FileAnalysis],
) -> list[dict]:
    """Run all enabled review passes (security, bug, performance, style).

    Each pass:
      1. Gets AST pre-filter signals (fast, deterministic)
      2. Builds a focused prompt with code + AST signals + context
      3. Calls LLM to reason and produce structured findings
      4. Merges AST + LLM findings with deduplication
    """
    # Determine LLM API key
    provider_name = config.get("llm_provider", "anthropic")
    api_key = (
        config.get("anthropic_api_key") if provider_name == "anthropic"
        else config.get("openai_api_key")
    )

    if not api_key:
        logger.warning(f"No API key for {provider_name} — running AST-only review")
        llm_provider = None
    else:
        try:
            llm_provider = create_llm_provider(provider_name, api_key)
        except Exception as e:
            logger.error(f"Failed to create LLM provider: {e}")
            llm_provider = None

    # Load prompt templates
    prompts = _load_prompt_templates()

    # Map pass names to reviewer classes
    reviewer_map = {
        "security": (SecurityReviewer, prompts.get("security", "")),
        "bug": (BugReviewer, prompts.get("bug", "")),
        "performance": (PerformanceReviewer, prompts.get("performance", "")),
        "style": (StyleReviewer, prompts.get("style", "")),
    }

    enabled_passes = config.get("review_passes", ["security", "bug", "performance", "style"])
    all_findings = []

    for file in python_files:
        filename = file.filename
        ctx = contexts.get(filename)
        ast_result = ast_results.get(filename)

        # Get the code to review (diff hunks or full content)
        code = _get_review_code(file, ctx)
        if not code:
            continue

        ast_dict = ast_result.to_dict() if ast_result else None
        ctx_dict = ctx.to_dict() if ctx else None
        # Add full_content to ctx_dict for prompt building
        if ctx_dict and ctx:
            ctx_dict["full_content"] = ctx.full_content
            ctx_dict["related_test_content"] = ctx.related_test_content
            ctx_dict["imported_module_signatures"] = ctx.imported_module_signatures

        for pass_name in enabled_passes:
            if pass_name not in reviewer_map:
                logger.warning(f"Unknown review pass: {pass_name}")
                continue

            reviewer_cls, prompt_template = reviewer_map[pass_name]

            if llm_provider is None:
                # AST-only mode: create reviewer with a dummy LLM that raises
                reviewer = reviewer_cls(
                    llm_provider=_NoOpLLM(),
                    prompt_template=prompt_template,
                )
            else:
                reviewer = reviewer_cls(
                    llm_provider=llm_provider,
                    prompt_template=prompt_template,
                )

            try:
                findings = reviewer.review(code, ast_analysis=ast_dict, context=ctx_dict)
                # Tag each finding with the file
                for f in findings:
                    f["file"] = filename
                    f.setdefault("category", pass_name)
                all_findings.extend(findings)
                logger.info(
                    f"[{pass_name}] {filename}: {len(findings)} findings"
                )
            except Exception as e:
                logger.error(f"[{pass_name}] {filename} failed: {e}")

    # Deduplicate across passes (same file + line + similar description)
    deduped = _deduplicate_findings(all_findings)
    logger.info(f"Total findings: {len(all_findings)} raw, {len(deduped)} after dedup")
    return deduped


class _NoOpLLM:
    """Dummy LLM that raises on any call — used for AST-only mode."""

    def analyze(self, prompt: str, system_prompt: str = "") -> str:
        raise RuntimeError("No LLM provider configured")

    def analyze_structured(self, prompt: str, system_prompt: str = "") -> list[dict]:
        raise RuntimeError("No LLM provider configured")


def _load_prompt_templates() -> dict[str, str]:
    """Load prompt templates from the prompts/ directory."""
    prompts = {}
    prompt_dir = os.path.join(os.path.dirname(__file__), "..", "prompts")

    template_files = {
        "security": "security_prompt.txt",
        "bug": "bug_prompt.txt",
        "performance": "performance_prompt.txt",
        "style": "style_prompt.txt",
    }

    for name, filename in template_files.items():
        filepath = os.path.join(prompt_dir, filename)
        try:
            with open(filepath) as f:
                prompts[name] = f.read()
        except FileNotFoundError:
            logger.warning(f"Prompt template not found: {filepath}")
            prompts[name] = ""

    return prompts


def _get_review_code(file, ctx) -> str:
    """Get the code to send for review.

    Prefers the full file content (for complete context), but falls back
    to reconstructing from diff hunks if full content isn't available.
    """
    if ctx and ctx.full_content:
        return ctx.full_content

    # Reconstruct from diff hunks (added lines only; context is not stored)
    lines = []
    for hunk in file.hunks:
        for change in hunk.lines:
            if change.is_addition:
                lines.append(change.content)
    return "\n".join(lines)


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate findings across review passes. See `src.dedup`."""
    return deduplicate_findings(findings)


def _post_review(
    github_client: GitHubClient,
    config: dict,
    pr_diff: PRDiff,
    findings: list[dict],
    pr_metadata: dict,
) -> None:
    """Post review findings as comments on the PR."""
    # Build file lookup
    file_map = {f.filename: f for f in pr_diff.files}

    comments = []
    for finding in findings:
        filename = finding.get("file", "")
        if filename not in file_map:
            continue

        file = file_map[filename]
        line_number = finding.get("line_number", 0)

        # Only comment on lines that are in the diff (additions)
        if line_number not in file.added_line_numbers:
            # Find the nearest added line
            added = file.added_line_numbers
            if added:
                line_number = min(added, key=lambda x: abs(x - line_number))
            else:
                continue

        comment = ReviewComment(
            path=filename,
            line=line_number,
            body=format_finding_as_comment(finding),
        )
        comments.append(comment)

    if not comments:
        logger.info("No comments to post (all findings outside diff).")
        return

    # Build summary
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    warning_count = sum(1 for f in findings if f.get("severity") == "warning")
    info_count = sum(1 for f in findings if f.get("severity") == "info")

    summary = (
        f"## AI Code Review Summary\n\n"
        f"Reviewed **{len(file_map)}** files and found **{len(findings)}** issues:\n"
        f"- 🔴 Critical: {critical_count}\n"
        f"- 🟡 Warning: {warning_count}\n"
        f"- 🔵 Info: {info_count}\n\n"
        f"_Review powered by AI Code Reviewer with AST analysis + multi-pass LLM reasoning._"
    )

    try:
        github_client.post_review(
            config["repo"], config["pr_number"], comments, summary
        )
    except Exception as e:
        logger.error(f"Failed to post review: {e}")
        # Fall back to posting individual comments
        for comment in comments:
            try:
                github_client.post_review_comment(
                    config["repo"],
                    config["pr_number"],
                    pr_metadata["head_sha"],
                    comment.path,
                    comment.line,
                    comment.body,
                )
            except Exception as e2:
                logger.error(f"Failed to post comment on {comment.path}:{comment.line}: {e2}")


def main() -> None:
    """CLI entry point."""
    setup_logging()
    config = get_config_from_env()

    if not config["github_token"]:
        logger.error("GITHUB_TOKEN is required")
        sys.exit(1)

    if not config["repo"]:
        logger.error("GITHUB_REPOSITORY is required")
        sys.exit(1)

    if config["pr_number"] == 0:
        logger.error("PR_NUMBER is required")
        sys.exit(1)

    result = run_review(config)
    logger.info(f"Review result: {json.dumps(result, indent=2)}")

    if result["status"] == "completed":
        logger.info(
            f"Done! Posted {result['posted_findings']} comments "
            f"on {result['files_reviewed']} files in {result['elapsed_seconds']}s"
        )


if __name__ == "__main__":
    main()
