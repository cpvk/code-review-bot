"""Tests for the AST analyzer module."""

import os

from src.ast_analyzer import (
    FileAnalysis,
    FunctionAnalysis,
    analyze_changed_functions,
    analyze_python_file,
    get_function_at_line,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(name: str) -> str:
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return f.read()


# ─── File-level analysis ───────────────────────────────────────────────────────


class TestAnalyzePythonFile:
    def test_empty_source(self):
        result = analyze_python_file("", "empty.py")
        assert isinstance(result, FileAnalysis)
        assert result.filename == "empty.py"
        assert len(result.functions) == 0

    def test_imports_extracted(self):
        result = analyze_python_file(_read_fixture("sample_vulnerable.py"), "vuln.py")
        assert "import os" in result.imports
        assert "import subprocess" in result.imports

    def test_functions_found(self):
        result = analyze_python_file(_read_fixture("sample_vulnerable.py"), "vuln.py")
        func_names = [f.name for f in result.functions]
        assert "get_user" in func_names
        assert "render_page" in func_names
        assert "run_command" in func_names
        assert "read_file" in func_names
        assert "process_data" in func_names
        assert "divide" in func_names
        assert "process_list" in func_names

    def test_global_variables(self):
        result = analyze_python_file(_read_fixture("sample_vulnerable.py"), "vuln.py")
        assert "API_KEY" in result.global_variables

    def test_security_concerns_detected(self):
        result = analyze_python_file(_read_fixture("sample_vulnerable.py"), "vuln.py")
        assert result.has_security_concerns is True

    def test_clean_file_no_security_concerns(self):
        result = analyze_python_file(_read_fixture("sample_clean.py"), "clean.py")
        # Clean file should have fewer/no security concerns
        all_security = []
        for func in result.all_functions:
            all_security.extend(func.security_sensitive_calls)
        # No dangerous calls like eval, exec, os.system etc
        dangerous_types = {"command_injection", "code_execution", "insecure_deserialization"}
        assert not any(s["type"] in dangerous_types for s in all_security)

    def test_total_lines(self):
        code = "line1\nline2\nline3\n"
        result = analyze_python_file(code, "test.py")
        assert result.total_lines == 4  # 3 lines + trailing newline

    def test_to_dict(self):
        result = analyze_python_file(_read_fixture("sample_clean.py"), "clean.py")
        d = result.to_dict()
        assert "filename" in d
        assert "imports" in d
        assert "functions" in d
        assert "classes" in d
        assert isinstance(d["functions"], list)


# ─── Function-level analysis ──────────────────────────────────────────────────


class TestFunctionAnalysis:
    """Test detailed function-level analysis."""

    def test_function_parameters(self):
        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.name == "add"
        assert "a: int" in func.parameters
        assert "b: int" in func.parameters

    def test_return_type(self):
        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.return_type == "int"

    def test_no_return_type(self):
        code = "def greet(name):\n    print(name)\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.return_type is None

    def test_self_excluded_from_params(self):
        code = "class Foo:\n    def bar(self, x):\n        pass\n"
        result = analyze_python_file(code, "test.py")
        method = result.class_methods[0]
        assert "self" not in method.parameters
        assert "x" in method.parameters

    def test_line_numbers(self):
        code = "# comment\n\ndef foo():\n    pass\n\ndef bar():\n    pass\n"
        result = analyze_python_file(code, "test.py")
        assert result.functions[0].name == "foo"
        assert result.functions[0].start_line == 3
        assert result.functions[1].name == "bar"
        assert result.functions[1].start_line == 6


# ─── Control flow analysis ────────────────────────────────────────────────────


class TestControlFlowAnalysis:
    def test_simple_function_complexity_1(self):
        code = "def foo():\n    return 42\n"
        result = analyze_python_file(code, "test.py")
        assert result.functions[0].cyclomatic_complexity == 1

    def test_if_increases_complexity(self):
        code = "def foo(x):\n    if x > 0:\n        return x\n    return 0\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.cyclomatic_complexity >= 2
        assert func.branch_count >= 1

    def test_loop_count(self):
        code = "def foo(items):\n    for item in items:\n        print(item)\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.loop_count >= 1

    def test_nested_loops(self):
        code = (
            "def foo(items):\n"
            "    for i in items:\n"
            "        for j in items:\n"
            "            print(i, j)\n"
        )
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.loop_count >= 2
        assert func.max_nesting_depth >= 2

    def test_nesting_depth_nested_if(self):
        code = (
            "def foo(x):\n"
            "    if x > 0:\n"
            "        if x > 10:\n"
            "            if x > 100:\n"
            "                return x\n"
        )
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.max_nesting_depth >= 3

    def test_process_list_complexity(self):
        """Test the sample_vulnerable.py process_list function — nested loops + if."""
        result = analyze_python_file(_read_fixture("sample_vulnerable.py"), "vuln.py")
        func = next(f for f in result.functions if f.name == "process_list")
        assert func.loop_count >= 2
        assert func.branch_count >= 1
        assert func.max_nesting_depth >= 2
        assert func.cyclomatic_complexity >= 3


# ─── Security detection ───────────────────────────────────────────────────────


class TestSecurityDetection:
    def test_os_system_detected(self):
        code = "def run(cmd):\n    os.system(cmd)\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        security_calls = func.security_sensitive_calls
        assert len(security_calls) >= 1
        assert any(s["type"] == "command_injection" for s in security_calls)

    def test_eval_detected(self):
        code = "def run(expr):\n    return eval(expr)\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        security_calls = func.security_sensitive_calls
        assert len(security_calls) >= 1
        assert any(s["type"] == "code_execution" for s in security_calls)

    def test_pickle_loads_detected(self):
        code = "def deserialize(data):\n    return pickle.loads(data)\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        security_calls = func.security_sensitive_calls
        assert len(security_calls) >= 1
        assert any(s["type"] == "insecure_deserialization" for s in security_calls)

    def test_fstring_in_db_query_detected(self):
        code = 'def get(uid):\n    db.execute(f"SELECT * FROM users WHERE id={uid}")\n'
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        security_calls = func.security_sensitive_calls
        assert any(s["type"] == "string_interpolation_in_query" for s in security_calls)

    def test_safe_parameterized_query_not_flagged(self):
        code = 'def get(uid):\n    db.execute("SELECT * FROM users WHERE id=%s", (uid,))\n'
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        security_calls = func.security_sensitive_calls
        # Should NOT have string_interpolation_in_query
        assert not any(s["type"] == "string_interpolation_in_query" for s in security_calls)

    def test_hardcoded_secret_in_global_vars(self):
        code = "API_KEY = 'sk-1234567890'\n\ndef foo():\n    pass\n"
        result = analyze_python_file(code, "test.py")
        assert "API_KEY" in result.global_variables


# ─── Call classification ──────────────────────────────────────────────────────


class TestCallClassification:
    def test_db_query_detected(self):
        code = "def foo():\n    db.execute('SELECT 1')\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert len(func.db_queries) >= 1

    def test_file_operations_detected(self):
        code = "def foo():\n    with open('file.txt') as f:\n        data = f.read()\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert len(func.file_operations) >= 1

    def test_network_call_detected(self):
        code = "def foo():\n    resp = requests.get('https://api.example.com')\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert len(func.network_calls) >= 1

    def test_external_calls_tracked(self):
        code = "def foo():\n    x = bar()\n    y = baz(x)\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert "bar" in func.external_calls
        assert "baz" in func.external_calls


# ─── Error handling analysis ──────────────────────────────────────────────────


class TestErrorHandling:
    def test_try_except_counted(self):
        code = (
            "def foo():\n"
            "    try:\n"
            "        pass\n"
            "    except ValueError:\n"
            "        pass\n"
        )
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.try_except_blocks >= 1

    def test_caught_exception_name(self):
        code = (
            "def foo():\n"
            "    try:\n"
            "        pass\n"
            "    except ValueError:\n"
            "        pass\n"
        )
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert "ValueError" in func.caught_exceptions

    def test_bare_except_detected(self):
        code = (
            "def foo():\n"
            "    try:\n"
            "        pass\n"
            "    except:\n"
            "        pass\n"
        )
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.has_bare_except is True

    def test_no_bare_except(self):
        code = (
            "def foo():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n"
        )
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert func.has_bare_except is False


# ─── Class analysis ───────────────────────────────────────────────────────────


class TestClassAnalysis:
    def test_class_detected(self):
        code = "class Foo:\n    pass\n"
        result = analyze_python_file(code, "test.py")
        assert "Foo" in result.classes

    def test_class_method_analyzed(self):
        code = (
            "class Foo:\n"
            "    def bar(self, x):\n"
            "        return x + 1\n"
        )
        result = analyze_python_file(code, "test.py")
        assert len(result.class_methods) == 1
        method = result.class_methods[0]
        assert method.name == "Foo.bar"
        assert "x" in method.parameters

    def test_multiple_methods(self):
        code = (
            "class Foo:\n"
            "    def bar(self):\n"
            "        pass\n"
            "    def baz(self, y: int):\n"
            "        pass\n"
        )
        result = analyze_python_file(code, "test.py")
        assert len(result.class_methods) == 2


# ─── Variable mutations ──────────────────────────────────────────────────────


class TestVariableMutations:
    def test_assignment_tracked(self):
        code = "def foo():\n    x = 1\n    x = 2\n"
        result = analyze_python_file(code, "test.py")
        func = result.functions[0]
        assert "x" in func.variable_mutations
        assert len(func.variable_mutations["x"]) == 2


# ─── Utility functions ────────────────────────────────────────────────────────


class TestUtilityFunctions:
    def test_analyze_changed_functions(self):
        code = (
            "def foo():\n"
            "    pass\n"
            "\n"
            "def bar():\n"
            "    pass\n"
            "\n"
            "def baz():\n"
            "    pass\n"
        )
        # Only lines 4-5 changed (bar function)
        result = analyze_changed_functions(code, [4, 5], "test.py")
        assert len(result) == 1
        assert result[0].name == "bar"

    def test_get_function_at_line(self):
        code = (
            "def foo():\n"
            "    pass\n"
            "\n"
            "def bar():\n"
            "    x = 1\n"
            "    return x\n"
        )
        func = get_function_at_line(code, 5, "test.py")
        assert func is not None
        assert func.name == "bar"

    def test_get_function_at_line_returns_none(self):
        code = "x = 1\n\ndef foo():\n    pass\n"
        func = get_function_at_line(code, 1, "test.py")
        assert func is None

    def test_to_dict_serializable(self):
        """Ensure to_dict output is JSON-serializable."""
        import json
        result = analyze_python_file(_read_fixture("sample_vulnerable.py"), "vuln.py")
        d = result.to_dict()
        json_str = json.dumps(d)
        assert isinstance(json_str, str)
