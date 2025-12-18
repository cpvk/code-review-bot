"""Tests for the reviewer modules (Phase 3).

Tests the AST pre-filter logic (deterministic, no LLM) and the
full review flow with a mock LLM provider.
"""

import json
import os

from src.ast_analyzer import analyze_python_file
from src.reviewers.security_reviewer import SecurityReviewer
from src.reviewers.bug_reviewer import BugReviewer
from src.reviewers.performance_reviewer import PerformanceReviewer
from src.reviewers.style_reviewer import StyleReviewer

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(name: str) -> str:
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return f.read()


# ─── Mock LLM ────────────────────────────────────────────────────────────────


class MockLLM:
    """Mock LLM that returns pre-configured findings."""

    def __init__(self, findings=None):
        self.findings = findings or []
        self.last_prompt = None
        self.call_count = 0

    def analyze(self, prompt: str, system_prompt: str = "") -> str:
        self.last_prompt = prompt
        self.call_count += 1
        return json.dumps(self.findings)

    def analyze_structured(self, prompt: str, system_prompt: str = "") -> list[dict]:
        self.last_prompt = prompt
        self.call_count += 1
        return self.findings


class FailingLLM:
    """Mock LLM that always raises."""

    def analyze(self, prompt: str, system_prompt: str = "") -> str:
        raise RuntimeError("LLM unavailable")

    def analyze_structured(self, prompt: str, system_prompt: str = "") -> list[dict]:
        raise RuntimeError("LLM unavailable")


# ─── Security Reviewer ───────────────────────────────────────────────────────


class TestSecurityReviewerASTPreFilter:
    """Test SecurityReviewer AST pre-filter (no LLM)."""

    def test_detects_command_injection(self):
        code = "def run(cmd):\n    os.system(cmd)\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert len(findings) >= 1
        assert any("command" in f["issue_description"].lower() for f in findings)

    def test_detects_code_execution(self):
        code = "def run(expr):\n    return eval(expr)\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("code execution" in f["issue_description"].lower() or "eval" in f["issue_description"].lower() for f in findings)

    def test_detects_insecure_deserialization(self):
        code = "def load(data):\n    return pickle.loads(data)\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("deserializ" in f["issue_description"].lower() for f in findings)

    def test_detects_sql_injection(self):
        code = 'def get(uid):\n    db.execute(f"SELECT * FROM users WHERE id={uid}")\n'
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("sql injection" in f["issue_description"].lower() or "interpolation" in f["issue_description"].lower() for f in findings)

    def test_detects_hardcoded_secret(self):
        code = 'API_KEY = "sk-1234567890"\n\ndef foo():\n    pass\n'
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("secret" in f["issue_description"].lower() or "API_KEY" in f["issue_description"] for f in findings)

    def test_clean_code_no_findings(self):
        code = _read_fixture("sample_clean.py")
        ast = analyze_python_file(code, "clean.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        # Clean code should have no critical security findings
        critical = [f for f in findings if f["severity"] == "critical"]
        assert len(critical) == 0

    def test_vulnerable_code_multiple_findings(self):
        code = _read_fixture("sample_vulnerable.py")
        ast = analyze_python_file(code, "vuln.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert len(findings) >= 3  # At least: command injection, deserialization, SQL injection


class TestSecurityReviewerFullFlow:
    """Test SecurityReviewer with mock LLM."""

    def test_review_with_llm(self):
        code = "def run(cmd):\n    os.system(cmd)\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        mock_llm = MockLLM(findings=[{
            "line_number": 2,
            "severity": "critical",
            "category": "security",
            "issue_description": "os.system with user input",
            "suggested_fix": "subprocess.run([cmd], shell=False)",
            "confidence": 0.95,
        }])
        reviewer = SecurityReviewer(llm_provider=mock_llm, prompt_template="Review this code.")
        findings = reviewer.review(code, ast_analysis=ast)
        assert len(findings) >= 1
        assert mock_llm.call_count == 1

    def test_skips_llm_for_clean_code(self):
        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        mock_llm = MockLLM()
        reviewer = SecurityReviewer(llm_provider=mock_llm, prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        assert len(findings) == 0
        assert mock_llm.call_count == 0  # LLM not called

    def test_fallback_to_ast_on_llm_failure(self):
        code = "def run(cmd):\n    os.system(cmd)\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=FailingLLM(), prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        # Should still return AST-only findings
        assert len(findings) >= 1

    def test_finding_has_correct_category(self):
        code = "def run(cmd):\n    os.system(cmd)\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        for f in findings:
            assert f["category"] == "security"


# ─── Bug Reviewer ────────────────────────────────────────────────────────────


class TestBugReviewerASTPreFilter:
    """Test BugReviewer AST pre-filter."""

    def test_detects_bare_except(self):
        code = "def foo():\n    try:\n        pass\n    except:\n        pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = BugReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("bare" in f["issue_description"].lower() for f in findings)

    def test_detects_io_without_error_handling(self):
        code = "def read():\n    with open('file.txt') as f:\n        return f.read()\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = BugReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("error handling" in f["issue_description"].lower() for f in findings)

    def test_no_false_positive_on_handled_io(self):
        code = (
            "def read():\n"
            "    try:\n"
            "        with open('file.txt') as f:\n"
            "            return f.read()\n"
            "    except FileNotFoundError:\n"
            "        return None\n"
        )
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = BugReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        # Should NOT flag I/O without error handling
        io_findings = [f for f in findings if "error handling" in f["issue_description"].lower()]
        assert len(io_findings) == 0


class TestBugReviewerFullFlow:
    def test_review_with_llm(self):
        code = "def foo():\n    try:\n        pass\n    except:\n        pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        mock_llm = MockLLM(findings=[{
            "line_number": 4,
            "severity": "warning",
            "category": "bug",
            "issue_description": "Bare except catches everything",
            "suggested_fix": "except Exception as e:",
            "confidence": 0.9,
        }])
        reviewer = BugReviewer(llm_provider=mock_llm, prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        assert len(findings) >= 1

    def test_finding_has_correct_category(self):
        code = "def foo():\n    try:\n        pass\n    except:\n        pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = BugReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        for f in findings:
            assert f["category"] == "bug"


# ─── Performance Reviewer ────────────────────────────────────────────────────


class TestPerformanceReviewerASTPreFilter:
    """Test PerformanceReviewer AST pre-filter."""

    def test_detects_nested_loops(self):
        code = (
            "def foo(items):\n"
            "    for i in items:\n"
            "        for j in items:\n"
            "            print(i, j)\n"
        )
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = PerformanceReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("nested loop" in f["issue_description"].lower() or "O(n^2)" in f["issue_description"] for f in findings)

    def test_detects_n_plus_1_query(self):
        code = (
            "def fetch():\n"
            "    users = db.query('SELECT * FROM users')\n"
            "    for user in users:\n"
            "        posts = db.query('SELECT * FROM posts')\n"
        )
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = PerformanceReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("n+1" in f["issue_description"].lower() or "database" in f["issue_description"].lower() for f in findings)

    def test_no_findings_for_simple_code(self):
        code = "def add(a, b):\n    return a + b\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = PerformanceReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert len(findings) == 0

    def test_skips_llm_when_no_signals(self):
        code = "def add(a, b):\n    return a + b\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        mock_llm = MockLLM()
        reviewer = PerformanceReviewer(llm_provider=mock_llm, prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        assert len(findings) == 0
        assert mock_llm.call_count == 0


class TestPerformanceReviewerFullFlow:
    def test_review_vulnerable_file(self):
        code = _read_fixture("sample_vulnerable.py")
        ast = analyze_python_file(code, "vuln.py").to_dict()
        mock_llm = MockLLM()
        reviewer = PerformanceReviewer(llm_provider=mock_llm, prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        # Should find nested loops and/or N+1 patterns
        assert len(findings) >= 1

    def test_finding_has_correct_category(self):
        code = (
            "def foo(items):\n"
            "    for i in items:\n"
            "        for j in items:\n"
            "            print(i, j)\n"
        )
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = PerformanceReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        for f in findings:
            assert f["category"] == "performance"


# ─── Style Reviewer ──────────────────────────────────────────────────────────


class TestStyleReviewerASTPreFilter:
    """Test StyleReviewer AST pre-filter."""

    def test_detects_too_many_params(self):
        code = "def foo(a, b, c, d, e, f, g):\n    pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = StyleReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("parameter" in f["issue_description"].lower() for f in findings)

    def test_detects_missing_return_type(self):
        code = "def foo(x):\n    return x + 1\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = StyleReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("return type" in f["issue_description"].lower() for f in findings)

    def test_does_not_flag_private_missing_return_type(self):
        code = "def _helper(x):\n    return x + 1\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = StyleReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        return_type_findings = [f for f in findings if "return type" in f["issue_description"].lower()]
        assert len(return_type_findings) == 0

    def test_detects_high_complexity(self):
        # Build a function with high cyclomatic complexity
        code = (
            "def complex_func(x):\n"
            "    if x > 0:\n"
            "        if x > 10:\n"
            "            if x > 100:\n"
            "                if x > 1000:\n"
            "                    if x > 10000:\n"
            "                        if x > 100000:\n"
            "                            if x > 1000000:\n"
            "                                if x > 10000000:\n"
            "                                    if x > 100000000:\n"
            "                                        if x > 1000000000:\n"
            "                                            return 'big'\n"
            "    return 'small'\n"
        )
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = StyleReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert any("complexity" in f["issue_description"].lower() for f in findings)

    def test_no_findings_for_simple_annotated_code(self):
        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = StyleReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer._ast_pre_filter(code, ast)
        assert len(findings) == 0


class TestStyleReviewerFullFlow:
    def test_review_with_llm(self):
        code = "def foo(a, b, c, d, e, f, g):\n    pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        mock_llm = MockLLM()
        reviewer = StyleReviewer(llm_provider=mock_llm, prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        assert len(findings) >= 1

    def test_finding_has_correct_category(self):
        code = "def foo(a, b, c, d, e, f, g):\n    pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = StyleReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        for f in findings:
            assert f["category"] == "style"


# ─── Cross-cutting tests ─────────────────────────────────────────────────────


class TestReviewerMergeLogic:
    """Test the merge/dedup logic shared across reviewers."""

    def test_llm_overrides_ast_at_same_line(self):
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        ast_findings = [{"line_number": 5, "confidence": 0.7, "severity": "warning", "issue_description": "AST finding"}]
        llm_findings = [{"line_number": 5, "confidence": 0.9, "severity": "critical", "issue_description": "LLM finding"}]
        merged = reviewer._merge_findings(ast_findings, llm_findings)
        assert len(merged) == 1
        assert merged[0]["severity"] == "critical"
        assert merged[0]["source"] == "llm"

    def test_keeps_both_at_different_lines(self):
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        ast_findings = [{"line_number": 5, "confidence": 0.7, "issue_description": "AST"}]
        llm_findings = [{"line_number": 10, "confidence": 0.9, "issue_description": "LLM"}]
        merged = reviewer._merge_findings(ast_findings, llm_findings)
        assert len(merged) == 2

    def test_ast_retained_when_llm_confidence_lower(self):
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        ast_findings = [{"line_number": 5, "confidence": 0.9, "issue_description": "AST"}]
        llm_findings = [{"line_number": 5, "confidence": 0.5, "issue_description": "LLM"}]
        merged = reviewer._merge_findings(ast_findings, llm_findings)
        assert len(merged) == 1
        assert merged[0]["issue_description"] == "AST"


class TestPromptBuilding:
    """Test that prompts include the right signals."""

    def test_security_prompt_includes_ast_findings(self):
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="SYSTEM PROMPT")
        ast_findings = [{"line_number": 5, "severity": "critical", "issue_description": "SQL injection found"}]
        prompt = reviewer._build_security_prompt("code", None, None, ast_findings)
        assert "SYSTEM PROMPT" in prompt
        assert "SQL injection found" in prompt
        assert "code" in prompt

    def test_bug_prompt_includes_control_flow(self):
        code = "def foo():\n    try:\n        pass\n    except:\n        pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = BugReviewer(llm_provider=MockLLM(), prompt_template="BUG PROMPT")
        prompt = reviewer._build_bug_prompt(code, ast, None, [])
        assert "BUG PROMPT" in prompt
        assert "error_handling" in prompt

    def test_perf_prompt_includes_complexity(self):
        code = "def foo(items):\n    for i in items:\n        print(i)\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = PerformanceReviewer(llm_provider=MockLLM(), prompt_template="PERF PROMPT")
        prompt = reviewer._build_perf_prompt(code, ast, None, [])
        assert "PERF PROMPT" in prompt
        assert "complexity" in prompt.lower()

    def test_style_prompt_includes_parameters(self):
        code = "def foo(a, b, c):\n    pass\n"
        ast = analyze_python_file(code, "test.py").to_dict()
        reviewer = StyleReviewer(llm_provider=MockLLM(), prompt_template="STYLE PROMPT")
        prompt = reviewer._build_style_prompt(code, ast, None, [])
        assert "STYLE PROMPT" in prompt
        assert "parameters" in prompt.lower()


# ─── Integration: vulnerable fixture through all reviewers ───────────────────


class TestVulnerableFileIntegration:
    """Run all reviewers on sample_vulnerable.py to verify end-to-end."""

    def test_security_finds_issues_in_vulnerable(self):
        code = _read_fixture("sample_vulnerable.py")
        ast = analyze_python_file(code, "vuln.py").to_dict()
        reviewer = SecurityReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        assert len(findings) >= 3
        severities = {f["severity"] for f in findings}
        assert "critical" in severities

    def test_performance_finds_issues_in_vulnerable(self):
        code = _read_fixture("sample_vulnerable.py")
        ast = analyze_python_file(code, "vuln.py").to_dict()
        reviewer = PerformanceReviewer(llm_provider=MockLLM(), prompt_template="")
        findings = reviewer.review(code, ast_analysis=ast)
        assert len(findings) >= 1  # Nested loops, N+1 query

    def test_clean_file_minimal_findings(self):
        code = _read_fixture("sample_clean.py")
        ast = analyze_python_file(code, "clean.py").to_dict()
        mock_llm = MockLLM()
        sec = SecurityReviewer(llm_provider=mock_llm, prompt_template="")
        perf = PerformanceReviewer(llm_provider=MockLLM(), prompt_template="")
        sec_findings = sec.review(code, ast_analysis=ast)
        perf_findings = perf.review(code, ast_analysis=ast)
        # Clean file should have zero critical findings
        all_critical = [f for f in sec_findings + perf_findings if f["severity"] == "critical"]
        assert len(all_critical) == 0
