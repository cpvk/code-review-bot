"""Tests for the context gatherer module."""

from src.context_gatherer import (
    FileContext,
    extract_imports,
    find_similar_function_names,
    find_test_file_candidates,
    resolve_import_to_filepath,
)


# ─── Import extraction ─────────────────────────────────────────────────────────


class TestExtractImports:
    def test_simple_import(self):
        code = "import os\nimport sys\n"
        result = extract_imports(code)
        assert "os" in result
        assert "sys" in result

    def test_from_import(self):
        code = "from os.path import join\n"
        result = extract_imports(code)
        assert "os.path" in result

    def test_dotted_import(self):
        code = "import os.path\n"
        result = extract_imports(code)
        assert "os.path" in result

    def test_mixed_imports(self):
        code = (
            "import os\n"
            "import sys\n"
            "from typing import Optional, List\n"
            "from src.utils import helper\n"
        )
        result = extract_imports(code)
        assert "os" in result
        assert "sys" in result
        assert "typing" in result
        assert "src.utils" in result

    def test_no_imports(self):
        code = "x = 1\nprint(x)\n"
        result = extract_imports(code)
        assert result == []

    def test_deduplication(self):
        code = "import os\nimport os\n"
        result = extract_imports(code)
        assert result.count("os") == 1


# ─── Import resolution ────────────────────────────────────────────────────────


class TestResolveImportToFilepath:
    def test_simple_module(self):
        candidates = resolve_import_to_filepath("os", "src/main.py")
        assert "os.py" in candidates

    def test_dotted_module(self):
        candidates = resolve_import_to_filepath("src.utils", "src/main.py")
        assert "src/utils.py" in candidates
        assert "src/utils/__init__.py" in candidates

    def test_relative_resolution(self):
        candidates = resolve_import_to_filepath("utils", "src/main.py")
        assert "utils.py" in candidates
        assert "src/utils.py" in candidates

    def test_deep_module(self):
        candidates = resolve_import_to_filepath("src.reviewers.base_reviewer", "src/main.py")
        assert "src/reviewers/base_reviewer.py" in candidates


# ─── Test file discovery ───────────────────────────────────────────────────────


class TestFindTestFileCandidates:
    def test_standard_file(self):
        candidates = find_test_file_candidates("src/utils.py")
        assert "tests/test_utils.py" in candidates

    def test_includes_unit_tests(self):
        candidates = find_test_file_candidates("src/utils.py")
        assert "tests/unit/test_utils.py" in candidates

    def test_includes_same_dir_test(self):
        candidates = find_test_file_candidates("src/utils.py")
        assert "src/test_utils.py" in candidates

    def test_nested_path(self):
        candidates = find_test_file_candidates("src/reviewers/security_reviewer.py")
        assert "tests/test_security_reviewer.py" in candidates
        assert "tests/src/reviewers/test_security_reviewer.py" in candidates


# ─── Function similarity ──────────────────────────────────────────────────────


class TestFindSimilarFunctionNames:
    def test_finds_similar_names(self):
        files = {
            "a.py": "def get_user_by_id(uid):\n    pass\n",
            "b.py": "def get_user_by_name(name):\n    pass\n",
        }
        similar = find_similar_function_names(
            ["get_user_by_id"],
            files,
            exclude_file="a.py",
        )
        assert len(similar) >= 1
        assert any(s["function_name"] == "get_user_by_name" for s in similar)

    def test_excludes_self(self):
        files = {
            "a.py": "def get_user(uid):\n    pass\n",
        }
        similar = find_similar_function_names(
            ["get_user"],
            files,
            exclude_file="a.py",
        )
        assert len(similar) == 0

    def test_no_match_for_unrelated(self):
        files = {
            "b.py": "def calculate_tax(amount):\n    pass\n",
        }
        similar = find_similar_function_names(
            ["get_user"],
            files,
        )
        assert len(similar) == 0


# ─── FileContext ──────────────────────────────────────────────────────────────


class TestFileContext:
    def test_to_dict(self):
        ctx = FileContext(
            filename="test.py",
            full_content="print('hello')",
            imports=["os", "sys"],
        )
        d = ctx.to_dict()
        assert d["filename"] == "test.py"
        assert d["has_full_content"] is True
        assert "os" in d["imports"]

    def test_to_prompt_context(self):
        ctx = FileContext(
            filename="test.py",
            full_content="print('hello')",
            recent_commits=["abc1234 initial commit"],
        )
        prompt = ctx.to_prompt_context()
        assert "test.py" in prompt
        assert "print('hello')" in prompt
        assert "abc1234" in prompt

    def test_empty_context(self):
        ctx = FileContext(filename="test.py")
        d = ctx.to_dict()
        assert d["has_full_content"] is False
        assert d["imports"] == []
