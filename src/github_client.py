"""
GitHub Client Module
Handles all GitHub API interactions: authentication, fetching PR data,
and posting review comments.
"""

from __future__ import annotations

import logging
import os

from github import Auth, Github
from github.PullRequest import PullRequest
from github.Repository import Repository

from .comment_formatter import format_review_comment
from .diff_parser import ChangedFile

logger = logging.getLogger(__name__)


class GitHubClient:
    """Wrapper around GitHub API for code review operations."""

    def __init__(self, token: str | None = None):
        token = token or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ValueError(
                "GitHub token required. Set GITHUB_TOKEN env var or pass token directly."
            )
        auth = Auth.Token(token)
        self._github = Github(auth=auth)

    def get_repo(self, repo_full_name: str) -> Repository:
        """Get a repository by its full name (owner/repo)."""
        return self._github.get_repo(repo_full_name)

    def get_pull_request(self, repo_full_name: str, pr_number: int) -> PullRequest:
        """Get a specific pull request."""
        repo = self.get_repo(repo_full_name)
        return repo.get_pull(pr_number)

    def get_pr_diff(self, repo_full_name: str, pr_number: int) -> str:
        """Fetch the raw diff for a pull request.

        Returns the unified diff text.
        """
        pr = self.get_pull_request(repo_full_name, pr_number)
        # PyGithub doesn't have a direct diff method, so we fetch via files
        # But we can construct from file patches
        files = pr.get_files()
        diff_parts = []
        for f in files:
            if f.patch:
                diff_parts.append(
                    f"diff --git a/{f.filename} b/{f.filename}\n"
                    f"--- a/{f.filename}\n"
                    f"+++ b/{f.filename}\n"
                    f"{f.patch}"
                )
        return "\n".join(diff_parts)

    def get_pr_files(self, repo_full_name: str, pr_number: int) -> list[dict]:
        """Fetch the list of changed files for a PR.

        Returns list of dicts with filename, status, patch, etc.
        """
        pr = self.get_pull_request(repo_full_name, pr_number)
        files = []
        for f in pr.get_files():
            files.append({
                "filename": f.filename,
                "status": f.status,
                "additions": f.additions,
                "deletions": f.deletions,
                "changes": f.changes,
                "patch": f.patch or "",
                "previous_filename": f.previous_filename,
            })
        return files

    def get_file_content(
        self, repo_full_name: str, file_path: str, ref: str | None = None
    ) -> str | None:
        """Fetch the content of a file from the repository.

        Args:
            repo_full_name: owner/repo
            file_path: Path to the file in the repo
            ref: Git ref (branch, commit sha). Defaults to default branch.

        Returns:
            File content as string, or None if file not found.
        """
        try:
            repo = self.get_repo(repo_full_name)
            kwargs = {"ref": ref} if ref else {}
            content = repo.get_contents(file_path, **kwargs)
            if isinstance(content, list):
                return None  # It's a directory
            return content.decoded_content.decode("utf-8")
        except Exception:
            logger.debug(f"Could not fetch file: {file_path}")
            return None

    def post_review_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
        side: str = "RIGHT",
    ) -> None:
        """Post an inline review comment on a specific line of a PR.

        Args:
            repo_full_name: owner/repo
            pr_number: PR number
            commit_sha: The commit SHA to comment on
            path: File path relative to repo root
            line: Line number in the diff to comment on
            body: Comment body (markdown)
            side: LEFT (old code) or RIGHT (new code)
        """
        pr = self.get_pull_request(repo_full_name, pr_number)
        pr.create_review_comment(
            body=body,
            commit=self._github.get_repo(repo_full_name).get_commit(commit_sha),
            path=path,
            line=line,
            side=side,
        )
        logger.info(f"Posted review comment on {path}:{line}")

    def post_review(
        self,
        repo_full_name: str,
        pr_number: int,
        comments: list[ReviewComment],
        summary: str,
    ) -> None:
        """Post a complete review with multiple inline comments.

        Args:
            repo_full_name: owner/repo
            pr_number: PR number
            comments: List of ReviewComment objects
            summary: Overall review summary body
        """
        pr = self.get_pull_request(repo_full_name, pr_number)
        commit = pr.get_commits().reversed[0]

        review_comments = []
        for comment in comments:
            review_comments.append({
                "path": comment.path,
                "line": comment.line,
                "side": comment.side,
                "body": comment.body,
            })

        pr.create_review(
            commit=commit,
            body=summary,
            event="COMMENT",
            comments=review_comments,
        )
        logger.info(
            f"Posted review with {len(review_comments)} comments on PR #{pr_number}"
        )

    def get_pr_metadata(self, repo_full_name: str, pr_number: int) -> dict:
        """Get metadata about a PR (title, description, author, etc.)."""
        pr = self.get_pull_request(repo_full_name, pr_number)
        return {
            "title": pr.title,
            "body": pr.body or "",
            "author": pr.user.login,
            "base_branch": pr.base.ref,
            "head_branch": pr.head.ref,
            "head_sha": pr.head.sha,
            "base_sha": pr.base.sha,
            "created_at": pr.created_at.isoformat(),
            "changed_files": pr.changed_files,
            "additions": pr.additions,
            "deletions": pr.deletions,
        }

    def close(self) -> None:
        """Close the GitHub connection."""
        self._github.close()


class ReviewComment:
    """A review comment to be posted on a PR."""

    def __init__(self, path: str, line: int, body: str, side: str = "RIGHT"):
        self.path = path
        self.line = line
        self.body = body
        self.side = side

    @classmethod
    def from_finding(cls, finding: dict, file: ChangedFile) -> ReviewComment:
        """Create a ReviewComment from a review finding dict.

        Args:
            finding: Dict with line_number, severity, category,
                     issue_description, suggested_fix, confidence
            file: The ChangedFile this finding belongs to
        """
        body = format_finding_as_comment(finding)
        return cls(
            path=file.filename,
            line=finding["line_number"],
            body=body,
        )


def format_finding_as_comment(finding: dict) -> str:
    """Format a single finding as a GitHub review comment body.

    Delegates to the canonical formatter in `comment_formatter`.
    """
    return format_review_comment(finding)
