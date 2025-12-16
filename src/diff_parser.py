"""
Diff Parser Module
Parses GitHub PR diffs into structured format for analysis.
Extracts changed files, hunks, and line-level changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from unidiff import PatchSet


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"


@dataclass
class ChangedLine:
    """A single changed line in a diff."""

    line_number: int  # Line number in the new file
    source_line_number: int | None  # Line number in the old file (None for additions)
    content: str
    is_addition: bool
    is_removal: bool


@dataclass
class DiffHunk:
    """A contiguous block of changes within a file."""

    source_start: int
    source_length: int
    target_start: int
    target_length: int
    section_header: str  # e.g., function name from @@ header
    lines: list[ChangedLine] = field(default_factory=list)

    @property
    def added_lines(self) -> list[ChangedLine]:
        return [line for line in self.lines if line.is_addition]

    @property
    def removed_lines(self) -> list[ChangedLine]:
        return [line for line in self.lines if line.is_removal]


@dataclass
class ChangedFile:
    """A file that was modified in the PR."""

    filename: str
    old_filename: str | None  # Set if file was renamed
    change_type: ChangeType
    hunks: list[DiffHunk] = field(default_factory=list)
    patch: str = ""  # Raw patch text

    @property
    def added_lines(self) -> list[ChangedLine]:
        lines = []
        for hunk in self.hunks:
            lines.extend(hunk.added_lines)
        return lines

    @property
    def removed_lines(self) -> list[ChangedLine]:
        lines = []
        for hunk in self.hunks:
            lines.extend(hunk.removed_lines)
        return lines

    @property
    def is_python(self) -> bool:
        return self.filename.endswith(".py")

    @property
    def added_line_numbers(self) -> list[int]:
        return [line.line_number for line in self.added_lines]


@dataclass
class PRDiff:
    """Complete parsed diff for a pull request."""

    files: list[ChangedFile] = field(default_factory=list)

    @property
    def python_files(self) -> list[ChangedFile]:
        return [f for f in self.files if f.is_python]

    @property
    def total_additions(self) -> int:
        return sum(len(f.added_lines) for f in self.files)

    @property
    def total_deletions(self) -> int:
        return sum(len(f.removed_lines) for f in self.files)


def parse_diff(diff_text: str) -> PRDiff:
    """Parse a unified diff string into structured PRDiff format.

    Args:
        diff_text: Raw unified diff text from GitHub API.

    Returns:
        PRDiff with all changed files, hunks, and lines.
    """
    pr_diff = PRDiff()

    if not diff_text or not diff_text.strip():
        return pr_diff

    patch_set = PatchSet(diff_text)

    for patched_file in patch_set:
        change_type = _determine_change_type(patched_file)
        old_filename = (
            patched_file.source_file.lstrip("a/")
            if change_type == ChangeType.RENAMED
            else None
        )

        changed_file = ChangedFile(
            filename=patched_file.target_file.lstrip("b/"),
            old_filename=old_filename,
            change_type=change_type,
            patch=str(patched_file),
        )

        for hunk in patched_file:
            diff_hunk = DiffHunk(
                source_start=hunk.source_start,
                source_length=hunk.source_length,
                target_start=hunk.target_start,
                target_length=hunk.target_length,
                section_header=hunk.section_header or "",
            )

            for line in hunk:
                if line.is_context:
                    continue

                changed_line = ChangedLine(
                    line_number=line.target_line_no or 0,
                    source_line_number=line.source_line_no,
                    content=line.value.rstrip("\n"),
                    is_addition=line.is_added,
                    is_removal=line.is_removed,
                )
                diff_hunk.lines.append(changed_line)

            changed_file.hunks.append(diff_hunk)

        pr_diff.files.append(changed_file)

    return pr_diff


def parse_github_pr_files(pr_files: list[dict]) -> PRDiff:
    """Parse PR files from GitHub API response (list of file objects).

    This handles the case where we get file data from the GitHub API
    (via PyGithub) rather than a raw diff string.

    Args:
        pr_files: List of file dicts from GitHub API, each with
                  filename, status, patch, etc.

    Returns:
        PRDiff with all changed files parsed.
    """
    pr_diff = PRDiff()

    for file_data in pr_files:
        filename = file_data.get("filename", "")
        status = file_data.get("status", "modified")
        patch = file_data.get("patch", "")

        change_type = {
            "added": ChangeType.ADDED,
            "removed": ChangeType.REMOVED,
            "modified": ChangeType.MODIFIED,
            "renamed": ChangeType.RENAMED,
        }.get(status, ChangeType.MODIFIED)

        changed_file = ChangedFile(
            filename=filename,
            old_filename=file_data.get("previous_filename"),
            change_type=change_type,
            patch=patch,
        )

        if patch:
            _parse_patch_into_hunks(changed_file, patch)

        pr_diff.files.append(changed_file)

    return pr_diff


def _determine_change_type(patched_file) -> ChangeType:
    """Determine the type of change for a patched file."""
    if patched_file.is_added_file:
        return ChangeType.ADDED
    elif patched_file.is_removed_file:
        return ChangeType.REMOVED
    elif patched_file.is_rename:
        return ChangeType.RENAMED
    return ChangeType.MODIFIED


def _parse_patch_into_hunks(changed_file: ChangedFile, patch: str) -> None:
    """Parse a single file's patch text into hunks.

    Handles the @@ -start,len +start,len @@ format.
    """
    current_hunk = None
    target_line = 0
    source_line = 0

    for raw_line in patch.split("\n"):
        if raw_line.startswith("@@"):
            # Parse hunk header: @@ -source_start,source_len +target_start,target_len @@ section
            header_parts = raw_line.split("@@")
            range_info = header_parts[1].strip() if len(header_parts) > 1 else ""
            section_header = header_parts[2].strip() if len(header_parts) > 2 else ""

            source_info, target_info = _parse_range_info(range_info)

            current_hunk = DiffHunk(
                source_start=source_info[0],
                source_length=source_info[1],
                target_start=target_info[0],
                target_length=target_info[1],
                section_header=section_header,
            )
            changed_file.hunks.append(current_hunk)
            target_line = target_info[0]
            source_line = source_info[0]

        elif current_hunk is not None:
            if raw_line.startswith("+"):
                line = ChangedLine(
                    line_number=target_line,
                    source_line_number=None,
                    content=raw_line[1:],
                    is_addition=True,
                    is_removal=False,
                )
                current_hunk.lines.append(line)
                target_line += 1
            elif raw_line.startswith("-"):
                line = ChangedLine(
                    line_number=0,
                    source_line_number=source_line,
                    content=raw_line[1:],
                    is_addition=False,
                    is_removal=True,
                )
                current_hunk.lines.append(line)
                source_line += 1
            else:
                # Context line
                target_line += 1
                source_line += 1


def _parse_range_info(range_str: str) -> tuple[tuple[int, int], tuple[int, int]]:
    """Parse '-start,len +start,len' into ((source_start, source_len), (target_start, target_len))."""
    parts = range_str.split()
    source = (0, 0)
    target = (0, 0)

    for part in parts:
        if part.startswith("-"):
            nums = part[1:].split(",")
            source = (int(nums[0]), int(nums[1]) if len(nums) > 1 else 1)
        elif part.startswith("+"):
            nums = part[1:].split(",")
            target = (int(nums[0]), int(nums[1]) if len(nums) > 1 else 1)

    return source, target
