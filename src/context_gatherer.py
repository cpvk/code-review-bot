"""
Context Gatherer Module
Fetches related files from the repository to provide context for reviews.
The "secret sauce" for accurate reviews — the bot reads not just the diff
but also surrounding context, imports, tests, and related code.

Context gathered:
  - Full file content (not just the diff)
  - Imported modules and their function signatures
  - Existing tests for changed functions
  - Similar functions in the codebase
  - Recent commit messages for change intent
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .ast_analyzer import analyze_python_file

logger = logging.getLogger(__name__)


@dataclass
class FileContext:
    """Context gathered for a single changed file."""

    filename: str
    full_content: str | None = None
    imports: list[str] = field(default_factory=list)
    imported_module_paths: list[str] = field(default_factory=list)
    imported_module_signatures: dict[str, list[str]] = field(default_factory=dict)
    related_test_files: list[str] = field(default_factory=list)
    related_test_content: dict[str, str] = field(default_factory=dict)
    similar_functions: list[dict] = field(default_factory=list)
    recent_commits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "has_full_content": self.full_content is not None,
            "imports": self.imports,
            "imported_module_paths": self.imported_module_paths,
            "related_tests": self.related_test_files,
            "similar_functions_count": len(self.similar_functions),
            "recent_commits": self.recent_commits[:5],
        }

    def to_prompt_context(self) -> str:
        """Format context as text for inclusion in LLM prompts."""
        parts = []

        if self.full_content:
            parts.append(f"## Full file: {self.filename}")
            parts.append(f"```python\n{self.full_content}\n```")

        if self.imported_module_signatures:
            parts.append("## Imported module signatures")
            for module, signatures in self.imported_module_signatures.items():
                parts.append(f"### {module}")
                for sig in signatures:
                    parts.append(f"  - {sig}")

        if self.related_test_content:
            parts.append("## Existing tests")
            for test_file, content in self.related_test_content.items():
                parts.append(f"### {test_file}")
                parts.append(f"```python\n{content}\n```")

        if self.recent_commits:
            parts.append("## Recent commits for this file")
            for commit in self.recent_commits[:5]:
                parts.append(f"  - {commit}")

        return "\n\n".join(parts)


# ─── Import extraction ─────────────────────────────────────────────────────────

# Regex for 'import X' and 'from X import Y'
_RE_IMPORT = re.compile(r"^import\s+([\w.]+)", re.MULTILINE)
_RE_FROM_IMPORT = re.compile(r"^from\s+([\w.]+)\s+import", re.MULTILINE)


def extract_imports(source_code: str) -> list[str]:
    """Extract imported module names from Python source code.

    Returns module paths like: ['os', 'sys', 'typing', 'src.utils']
    """
    modules = set()
    for match in _RE_IMPORT.finditer(source_code):
        modules.add(match.group(1))
    for match in _RE_FROM_IMPORT.finditer(source_code):
        modules.add(match.group(1))
    return sorted(modules)


def resolve_import_to_filepath(module_name: str, source_filepath: str) -> list[str]:
    """Resolve a Python import to potential file paths in the repo.

    For 'from src.utils import foo', returns candidate paths like:
      ['src/utils.py', 'src/utils/__init__.py']

    Handles both relative and absolute imports.

    Args:
        module_name: Dotted module name (e.g., 'src.utils')
        source_filepath: Path of the importing file (e.g., 'src/main.py')

    Returns:
        List of candidate file paths to look for.
    """
    # Convert dots to path separators
    parts = module_name.split(".")

    # Try as a direct module file
    candidates = []
    module_path = "/".join(parts)
    candidates.append(f"{module_path}.py")
    candidates.append(f"{module_path}/__init__.py")

    # For relative imports, try from the same directory
    source_dir = str(PurePosixPath(source_filepath).parent)
    if source_dir and source_dir != ".":
        candidates.append(f"{source_dir}/{module_path}.py")
        candidates.append(f"{source_dir}/{module_path}/__init__.py")

    return candidates


# ─── Test file discovery ───────────────────────────────────────────────────────

def find_test_file_candidates(filename: str) -> list[str]:
    """Generate candidate test file paths for a given source file.

    For 'src/utils.py', generates:
      ['tests/test_utils.py', 'test_utils.py', 'src/test_utils.py',
       'tests/src/test_utils.py', 'tests/unit/test_utils.py']

    Args:
        filename: Path to the source file.

    Returns:
        List of candidate test file paths.
    """
    path = PurePosixPath(filename)
    base_name = path.stem  # e.g., 'utils'
    test_name = f"test_{base_name}.py"
    parent = str(path.parent)

    candidates = [
        f"tests/{test_name}",
        test_name,
        f"tests/unit/{test_name}",
        f"tests/integration/{test_name}",
    ]

    # Also try in the same directory structure under tests/
    if parent and parent != ".":
        candidates.append(f"{parent}/{test_name}")
        candidates.append(f"tests/{parent}/{test_name}")

    return candidates


# ─── Function similarity ──────────────────────────────────────────────────────

def find_similar_function_names(
    target_functions: list[str],
    all_file_contents: dict[str, str],
    exclude_file: str = "",
) -> list[dict]:
    """Find functions with similar names across the codebase.

    Uses simple name matching — looks for functions that share significant
    name tokens with the target functions.

    Args:
        target_functions: List of function names from the changed file.
        all_file_contents: Dict mapping file paths to their source code.
        exclude_file: File to exclude (the changed file itself).

    Returns:
        List of dicts with: filename, function_name, similarity_reason
    """
    similar = []
    target_tokens = set()
    for name in target_functions:
        # Split camelCase and snake_case
        tokens = set(re.split(r"[_A-Z]", name.lower()))
        tokens.discard("")
        target_tokens.update(tokens)

    for filepath, content in all_file_contents.items():
        if filepath == exclude_file:
            continue
        try:
            file_analysis = analyze_python_file(content, filepath)
            for func in file_analysis.all_functions:
                func_tokens = set(re.split(r"[_A-Z]", func.name.lower()))
                func_tokens.discard("")
                overlap = target_tokens & func_tokens
                if len(overlap) >= 2:  # At least 2 shared tokens
                    similar.append({
                        "filename": filepath,
                        "function_name": func.name,
                        "shared_tokens": list(overlap),
                        "lines": f"{func.start_line}-{func.end_line}",
                    })
        except Exception:
            continue

    return similar


# ─── Main gathering function ──────────────────────────────────────────────────

def gather_context(
    github_client,
    repo_name: str,
    filename: str,
    ref: str | None = None,
) -> FileContext:
    """Gather all relevant context for reviewing a file.

    Args:
        github_client: GitHubClient instance
        repo_name: owner/repo
        filename: Path to the file being reviewed
        ref: Git ref to fetch content from

    Returns:
        FileContext with all gathered information
    """
    context = FileContext(filename=filename)

    # 1. Fetch full file content
    content = github_client.get_file_content(repo_name, filename, ref=ref)
    context.full_content = content

    if not content:
        logger.warning(f"Could not fetch content for {filename}")
        return context

    # 2. Extract imports and resolve to file paths
    context.imports = extract_imports(content)
    for module in context.imports:
        candidates = resolve_import_to_filepath(module, filename)
        context.imported_module_paths.extend(candidates)

    # 3. Fetch imported module signatures
    for module in context.imports:
        candidates = resolve_import_to_filepath(module, filename)
        for candidate in candidates:
            module_content = github_client.get_file_content(repo_name, candidate, ref=ref)
            if module_content:
                try:
                    module_analysis = analyze_python_file(module_content, candidate)
                    signatures = []
                    for func in module_analysis.all_functions:
                        sig = f"def {func.name}({', '.join(func.parameters)})"
                        if func.return_type:
                            sig += f" -> {func.return_type}"
                        signatures.append(sig)
                    if signatures:
                        context.imported_module_signatures[module] = signatures
                except Exception as e:
                    logger.debug(f"Could not analyze module {candidate}: {e}")
                break  # Found the module file, stop looking

    # 4. Find and fetch related test files
    test_candidates = find_test_file_candidates(filename)
    for test_path in test_candidates:
        test_content = github_client.get_file_content(repo_name, test_path, ref=ref)
        if test_content:
            context.related_test_files.append(test_path)
            context.related_test_content[test_path] = test_content

    # 5. Get recent commit messages for the file
    try:
        repo = github_client.get_repo(repo_name)
        commits = repo.get_commits(path=filename)
        for commit in commits[:5]:
            msg = commit.commit.message.split("\n")[0]  # First line only
            context.recent_commits.append(f"{commit.sha[:7]} {msg}")
    except Exception as e:
        logger.debug(f"Could not fetch commits for {filename}: {e}")

    return context


def gather_context_local(
    filename: str,
    project_root: str,
) -> FileContext:
    """Gather context from local filesystem (for testing/local runs).

    Args:
        filename: Path to the file relative to project root.
        project_root: Absolute path to the project root directory.

    Returns:
        FileContext with locally gathered information.
    """
    context = FileContext(filename=filename)
    full_path = os.path.join(project_root, filename)

    # 1. Read full file content
    try:
        with open(full_path) as f:
            context.full_content = f.read()
    except FileNotFoundError:
        logger.warning(f"File not found: {full_path}")
        return context

    # 2. Extract imports
    context.imports = extract_imports(context.full_content)
    for module in context.imports:
        candidates = resolve_import_to_filepath(module, filename)
        context.imported_module_paths.extend(candidates)

    # 3. Analyze imported modules locally
    for module in context.imports:
        candidates = resolve_import_to_filepath(module, filename)
        for candidate in candidates:
            candidate_path = os.path.join(project_root, candidate)
            if os.path.isfile(candidate_path):
                try:
                    with open(candidate_path) as f:
                        module_content = f.read()
                    module_analysis = analyze_python_file(module_content, candidate)
                    signatures = []
                    for func in module_analysis.all_functions:
                        sig = f"def {func.name}({', '.join(func.parameters)})"
                        if func.return_type:
                            sig += f" -> {func.return_type}"
                        signatures.append(sig)
                    if signatures:
                        context.imported_module_signatures[module] = signatures
                except Exception as e:
                    logger.debug(f"Could not analyze {candidate}: {e}")
                break

    # 4. Find test files locally
    test_candidates = find_test_file_candidates(filename)
    for test_path in test_candidates:
        test_full_path = os.path.join(project_root, test_path)
        if os.path.isfile(test_full_path):
            try:
                with open(test_full_path) as f:
                    test_content = f.read()
                context.related_test_files.append(test_path)
                context.related_test_content[test_path] = test_content
            except Exception:
                pass

    return context
