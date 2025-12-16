"""Tests for the diff parser module."""

from src.diff_parser import (
    ChangeType,
    ChangedFile,
    PRDiff,
    parse_diff,
    parse_github_pr_files,
)


SAMPLE_DIFF = (
    "diff --git a/src/utils.py b/src/utils.py\n"
    "--- a/src/utils.py\n"
    "+++ b/src/utils.py\n"
    "@@ -10,4 +10,7 @@ def process_data(items):\n"
    "     results = []\n"
    "     for item in items:\n"
    "-        results.append(item.value)\n"
    "+        if item is not None:\n"
    "+            results.append(item.value)\n"
    "+        else:\n"
    "+            results.append(None)\n"
    "     return results\n"
)

SAMPLE_DIFF_NEW_FILE = (
    "diff --git a/src/new_module.py b/src/new_module.py\n"
    "new file mode 100644\n"
    "--- /dev/null\n"
    "+++ b/src/new_module.py\n"
    "@@ -0,0 +1,13 @@\n"
    "+import os\n"
    "+import sys\n"
    "+\n"
    "+\n"
    "+def hello():\n"
    "+    print(\"hello world\")\n"
    "+\n"
    "+\n"
    "+def fetch_data(url):\n"
    "+    import requests\n"
    "+    resp = requests.get(url)\n"
    "+    data = resp.json()\n"
    "+    return data\n"
)

SAMPLE_DIFF_MULTI_FILE = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n"
    "+++ b/src/auth.py\n"
    "@@ -5,2 +5,4 @@ def authenticate(username, password):\n"
    "     if username == \"admin\":\n"
    "-        return True\n"
    "+        query = f\"SELECT * FROM users WHERE name='{username}'\"\n"
    "+        result = db.execute(query)\n"
    "+        return result is not None\n"
    "diff --git a/tests/test_auth.py b/tests/test_auth.py\n"
    "--- a/tests/test_auth.py\n"
    "+++ b/tests/test_auth.py\n"
    "@@ -1,2 +1,5 @@\n"
    "+import pytest\n"
    "+\n"
    "+\n"
    " def test_authenticate():\n"
    "-    assert authenticate(\"admin\", \"pass\")\n"
    "+    assert authenticate(\"admin\", \"password123\")\n"
)


class TestParseDiff:
    def test_empty_diff(self):
        result = parse_diff("")
        assert isinstance(result, PRDiff)
        assert len(result.files) == 0

    def test_single_file_diff(self):
        result = parse_diff(SAMPLE_DIFF)
        assert len(result.files) == 1

        file = result.files[0]
        assert file.filename == "src/utils.py"
        assert file.change_type == ChangeType.MODIFIED
        assert file.is_python

    def test_single_file_has_hunks(self):
        result = parse_diff(SAMPLE_DIFF)
        file = result.files[0]
        assert len(file.hunks) == 1
        hunk = file.hunks[0]
        assert len(hunk.added_lines) > 0
        assert len(hunk.removed_lines) > 0

    def test_added_and_removed_counts(self):
        result = parse_diff(SAMPLE_DIFF)
        file = result.files[0]
        assert len(file.added_lines) == 4  # 4 new lines
        assert len(file.removed_lines) == 1  # 1 removed line

    def test_new_file_diff(self):
        result = parse_diff(SAMPLE_DIFF_NEW_FILE)
        assert len(result.files) == 1
        file = result.files[0]
        assert file.filename == "src/new_module.py"
        assert file.change_type == ChangeType.ADDED

    def test_multi_file_diff(self):
        result = parse_diff(SAMPLE_DIFF_MULTI_FILE)
        assert len(result.files) == 2
        assert result.files[0].filename == "src/auth.py"
        assert result.files[1].filename == "tests/test_auth.py"

    def test_python_files_filter(self):
        result = parse_diff(SAMPLE_DIFF_MULTI_FILE)
        py_files = result.python_files
        assert len(py_files) == 2

    def test_total_additions_deletions(self):
        result = parse_diff(SAMPLE_DIFF)
        assert result.total_additions == 4
        assert result.total_deletions == 1

    def test_line_numbers(self):
        result = parse_diff(SAMPLE_DIFF)
        file = result.files[0]
        added_numbers = file.added_line_numbers
        assert len(added_numbers) == 4
        # All line numbers should be positive
        assert all(n > 0 for n in added_numbers)


class TestParseGithubPrFiles:
    def test_parse_file_list(self):
        pr_files = [
            {
                "filename": "src/app.py",
                "status": "modified",
                "additions": 5,
                "deletions": 2,
                "changes": 7,
                "patch": "@@ -1,3 +1,6 @@\n+import os\n+\n def main():\n-    pass\n+    print('hello')\n+    return 0",
                "previous_filename": None,
            },
            {
                "filename": "README.md",
                "status": "modified",
                "additions": 1,
                "deletions": 0,
                "changes": 1,
                "patch": "@@ -1,2 +1,3 @@\n # Project\n+New line here",
                "previous_filename": None,
            },
        ]

        result = parse_github_pr_files(pr_files)
        assert len(result.files) == 2
        assert result.files[0].filename == "src/app.py"
        assert result.files[0].change_type == ChangeType.MODIFIED
        assert result.files[0].is_python
        assert not result.files[1].is_python

    def test_parse_renamed_file(self):
        pr_files = [
            {
                "filename": "src/new_name.py",
                "status": "renamed",
                "additions": 0,
                "deletions": 0,
                "changes": 0,
                "patch": "",
                "previous_filename": "src/old_name.py",
            },
        ]

        result = parse_github_pr_files(pr_files)
        assert result.files[0].change_type == ChangeType.RENAMED
        assert result.files[0].old_filename == "src/old_name.py"

    def test_empty_file_list(self):
        result = parse_github_pr_files([])
        assert len(result.files) == 0

    def test_python_files_filter(self):
        pr_files = [
            {"filename": "app.py", "status": "modified", "patch": "", "previous_filename": None},
            {"filename": "style.css", "status": "modified", "patch": "", "previous_filename": None},
            {"filename": "utils.py", "status": "added", "patch": "", "previous_filename": None},
        ]
        result = parse_github_pr_files(pr_files)
        assert len(result.python_files) == 2
