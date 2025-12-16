"""
AST Analyzer Module
Parses Python code into Abstract Syntax Trees using tree-sitter.
Extracts function signatures, control flow, external calls, data flow,
error handling patterns, and security-sensitive operations.

This is the core module that separates this project from a simple LLM wrapper.
It provides structured understanding of code BEFORE sending to the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

logger = logging.getLogger(__name__)

# Initialize tree-sitter parser once at module level
PY_LANGUAGE = Language(tspython.language())
_parser = Parser(PY_LANGUAGE)

# ─── Security-sensitive patterns ───────────────────────────────────────────────

DANGEROUS_CALLS = {
    "eval", "exec", "compile",  # Code execution
    "os.system", "os.popen",  # Shell commands
    "subprocess.call", "subprocess.run", "subprocess.Popen",  # Subprocess
    "pickle.loads", "pickle.load",  # Deserialization
    "yaml.load",  # Unsafe YAML (without SafeLoader)
    "__import__",  # Dynamic imports
}

DANGEROUS_FUNCTIONS = {
    "eval", "exec", "compile", "system", "popen",
    "loads", "load", "__import__",
}

DB_QUERY_PATTERNS = {"execute", "executemany", "raw", "query", "cursor"}
FILE_IO_PATTERNS = {"open", "read", "write", "readlines", "writelines"}
NETWORK_CALL_PATTERNS = {"get", "post", "put", "delete", "patch", "request", "fetch", "urlopen"}
NETWORK_MODULES = {"requests", "urllib", "http", "aiohttp", "httpx"}

# Node types that increase cyclomatic complexity
COMPLEXITY_NODE_TYPES = {
    "if_statement", "elif_clause", "for_statement", "while_statement",
    "except_clause", "with_statement", "assert_statement",
    "boolean_operator",  # and/or in conditions
    "conditional_expression",  # ternary
}

LOOP_NODE_TYPES = {"for_statement", "while_statement", "list_comprehension",
                   "set_comprehension", "dictionary_comprehension", "generator_expression"}

BRANCH_NODE_TYPES = {"if_statement", "elif_clause", "conditional_expression"}


# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class FunctionAnalysis:
    """Structured AST analysis for a single function."""

    name: str
    start_line: int
    end_line: int
    parameters: list[str] = field(default_factory=list)
    return_type: str | None = None
    decorators: list[str] = field(default_factory=list)
    # Control flow
    cyclomatic_complexity: int = 1
    max_nesting_depth: int = 0
    loop_count: int = 0
    branch_count: int = 0
    # External calls
    external_calls: list[str] = field(default_factory=list)
    db_queries: list[str] = field(default_factory=list)
    file_operations: list[str] = field(default_factory=list)
    network_calls: list[str] = field(default_factory=list)
    # Data flow
    variable_mutations: dict[str, list[int]] = field(default_factory=dict)
    # Error handling
    try_except_blocks: int = 0
    caught_exceptions: list[str] = field(default_factory=list)
    has_bare_except: bool = False
    # Security
    security_sensitive_calls: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization and LLM prompting."""
        return {
            "name": self.name,
            "lines": f"{self.start_line}-{self.end_line}",
            "parameters": self.parameters,
            "return_type": self.return_type,
            "decorators": self.decorators,
            "complexity": {
                "cyclomatic": self.cyclomatic_complexity,
                "max_nesting": self.max_nesting_depth,
                "loops": self.loop_count,
                "branches": self.branch_count,
            },
            "external_calls": self.external_calls,
            "db_queries": self.db_queries,
            "file_operations": self.file_operations,
            "network_calls": self.network_calls,
            "error_handling": {
                "try_except_blocks": self.try_except_blocks,
                "caught_exceptions": self.caught_exceptions,
                "has_bare_except": self.has_bare_except,
            },
            "security_sensitive_calls": self.security_sensitive_calls,
            "variable_mutations": {
                k: v for k, v in self.variable_mutations.items()
            },
        }


@dataclass
class FileAnalysis:
    """AST analysis for an entire file."""

    filename: str
    imports: list[str] = field(default_factory=list)
    functions: list[FunctionAnalysis] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    class_methods: list[FunctionAnalysis] = field(default_factory=list)
    global_variables: list[str] = field(default_factory=list)
    has_security_concerns: bool = False
    total_lines: int = 0

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "total_lines": self.total_lines,
            "imports": self.imports,
            "functions": [f.to_dict() for f in self.functions],
            "classes": self.classes,
            "class_methods": [m.to_dict() for m in self.class_methods],
            "global_variables": self.global_variables,
            "has_security_concerns": self.has_security_concerns,
        }

    @property
    def all_functions(self) -> list[FunctionAnalysis]:
        """All functions including class methods."""
        return self.functions + self.class_methods


# ─── Node text helper ──────────────────────────────────────────────────────────

def _node_text(node: Node, source: bytes) -> str:
    """Extract text content of a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8")


def _get_children_by_type(node: Node, type_name: str) -> list[Node]:
    """Get all direct children of a specific type."""
    return [child for child in node.children if child.type == type_name]


def _find_all_descendants(node: Node, type_name: str) -> list[Node]:
    """Recursively find all descendants of a specific type."""
    results = []
    if node.type == type_name:
        results.append(node)
    for child in node.children:
        results.extend(_find_all_descendants(child, type_name))
    return results


# ─── Main entry point ──────────────────────────────────────────────────────────

def analyze_python_file(source_code: str, filename: str = "<unknown>") -> FileAnalysis:
    """Analyze a Python source file using tree-sitter AST parsing.

    Args:
        source_code: Python source code as string.
        filename: Name of the file for identification.

    Returns:
        FileAnalysis with structured information about the code.
    """
    if not source_code or not source_code.strip():
        return FileAnalysis(filename=filename)

    source_bytes = source_code.encode("utf-8")
    tree = _parser.parse(source_bytes)
    root = tree.root_node

    analysis = FileAnalysis(
        filename=filename,
        total_lines=source_code.count("\n") + 1,
    )

    # Walk top-level nodes
    for node in root.children:
        if node.type in ("import_statement", "import_from_statement"):
            analysis.imports.append(_node_text(node, source_bytes))

        elif node.type == "expression_statement":
            # Check for global variable assignments
            child = node.children[0] if node.children else None
            if child and child.type == "assignment":
                var_name = _node_text(child.children[0], source_bytes)
                analysis.global_variables.append(var_name)

        elif node.type == "function_definition":
            func_analysis = _analyze_function(node, source_bytes)
            analysis.functions.append(func_analysis)

        elif node.type == "class_definition":
            class_name = _extract_class_name(node, source_bytes)
            analysis.classes.append(class_name)
            # Analyze methods inside the class
            class_body = node.child_by_field_name("body")
            if class_body:
                for child in class_body.children:
                    if child.type == "function_definition":
                        method = _analyze_function(child, source_bytes, class_name=class_name)
                        analysis.class_methods.append(method)

        elif node.type == "decorated_definition":
            # Handle decorated functions/classes
            inner = None
            for child in node.children:
                if child.type == "function_definition":
                    inner = child
                    break
                elif child.type == "class_definition":
                    inner = child
                    break
            if inner and inner.type == "function_definition":
                func_analysis = _analyze_function(inner, source_bytes)
                # Add decorator info
                for child in node.children:
                    if child.type == "decorator":
                        func_analysis.decorators.append(_node_text(child, source_bytes))
                analysis.functions.append(func_analysis)
            elif inner and inner.type == "class_definition":
                class_name = _extract_class_name(inner, source_bytes)
                analysis.classes.append(class_name)

    # Check for security concerns
    all_funcs = analysis.all_functions
    analysis.has_security_concerns = any(
        len(f.security_sensitive_calls) > 0 for f in all_funcs
    )

    return analysis


# ─── Function analysis ─────────────────────────────────────────────────────────

def _analyze_function(
    node: Node, source: bytes, class_name: str | None = None
) -> FunctionAnalysis:
    """Analyze a function/method definition node."""
    name = _extract_function_name(node, source)
    if class_name:
        name = f"{class_name}.{name}"

    analysis = FunctionAnalysis(
        name=name,
        start_line=node.start_point[0] + 1,  # 1-indexed
        end_line=node.end_point[0] + 1,
    )

    # Extract parameters
    params_node = node.child_by_field_name("parameters")
    if params_node:
        analysis.parameters = _extract_parameters(params_node, source)

    # Extract return type
    return_type_node = node.child_by_field_name("return_type")
    if return_type_node:
        analysis.return_type = _node_text(return_type_node, source)

    # Analyze the function body
    body_node = node.child_by_field_name("body")
    if body_node:
        _analyze_body(body_node, source, analysis, depth=0)

    return analysis


def _extract_function_name(node: Node, source: bytes) -> str:
    """Extract function name from a function_definition node."""
    name_node = node.child_by_field_name("name")
    return _node_text(name_node, source) if name_node else "<anonymous>"


def _extract_class_name(node: Node, source: bytes) -> str:
    """Extract class name from a class_definition node."""
    name_node = node.child_by_field_name("name")
    return _node_text(name_node, source) if name_node else "<anonymous>"


def _extract_parameters(params_node: Node, source: bytes) -> list[str]:
    """Extract parameter names (with type annotations) from a parameters node."""
    params = []
    for child in params_node.children:
        if child.type in ("identifier", "typed_parameter", "default_parameter",
                          "typed_default_parameter", "list_splat_pattern",
                          "dictionary_splat_pattern"):
            param_text = _node_text(child, source)
            # Skip 'self' and 'cls'
            if param_text not in ("self", "cls"):
                params.append(param_text)
    return params


# ─── Body analysis (recursive) ─────────────────────────────────────────────────

def _analyze_body(node: Node, source: bytes, analysis: FunctionAnalysis, depth: int) -> None:
    """Recursively analyze a block of code, extracting metrics.

    This walks the AST tree non-redundantly: calls are only analyzed once
    at the point they appear (expression_statement, return_statement, or
    assignment RHS), not again when recursion visits their child nodes.
    """
    for child in node.children:
        # Track nesting depth
        if child.type in ("if_statement", "for_statement", "while_statement",
                          "try_statement", "with_statement"):
            new_depth = depth + 1
            analysis.max_nesting_depth = max(analysis.max_nesting_depth, new_depth)

        # Cyclomatic complexity
        if child.type in COMPLEXITY_NODE_TYPES:
            analysis.cyclomatic_complexity += 1

        # Loops
        if child.type in LOOP_NODE_TYPES:
            analysis.loop_count += 1

        # Branches
        if child.type in BRANCH_NODE_TYPES:
            analysis.branch_count += 1

        # Try/except blocks
        if child.type == "try_statement":
            analysis.try_except_blocks += 1
            _analyze_try_except(child, source, analysis)

        # Expression statements — extract calls and assignments from within
        if child.type == "expression_statement":
            for sub in child.children:
                if sub.type == "call":
                    _analyze_call(sub, source, analysis)
                elif sub.type == "assignment":
                    _track_assignment(sub, source, analysis)
                    # Check RHS for calls
                    for rhs_call in _find_all_descendants(sub, "call"):
                        _analyze_call(rhs_call, source, analysis)
                elif sub.type == "augmented_assignment":
                    _track_assignment(sub, source, analysis)

        # Standalone assignment (outside expression_statement, e.g., in for body)
        elif child.type == "assignment":
            _track_assignment(child, source, analysis)
            for rhs_call in _find_all_descendants(child, "call"):
                _analyze_call(rhs_call, source, analysis)
        elif child.type == "augmented_assignment":
            _track_assignment(child, source, analysis)

        # Return statements — find all calls within
        elif child.type == "return_statement":
            for call_node in _find_all_descendants(child, "call"):
                _analyze_call(call_node, source, analysis)

        # with_statement — extract calls from with_clause (e.g., open() in 'with open(f) as h:')
        if child.type == "with_statement":
            for sub in child.children:
                if sub.type == "with_clause":
                    for call_node in _find_all_descendants(sub, "call"):
                        _analyze_call(call_node, source, analysis)

        # for_statement — extract calls from the iterator expression
        if child.type == "for_statement":
            # The iterator is the 3rd meaningful child after 'for', 'pattern', 'in'
            for sub in child.children:
                if sub.type == "call":
                    _analyze_call(sub, source, analysis)

        # Recurse into child blocks (control flow structures)
        # Only recurse into block-level structures, NOT into expression nodes
        # to avoid double-counting calls
        if child.type in (
            "block", "if_statement", "elif_clause", "else_clause",
            "for_statement", "while_statement",
            "try_statement", "except_clause", "finally_clause",
            "with_statement",
        ):
            inner_depth = depth + 1 if child.type in (
                "if_statement", "elif_clause", "else_clause",
                "for_statement", "while_statement",
                "try_statement", "except_clause", "finally_clause",
                "with_statement",
            ) else depth
            _analyze_body(child, source, analysis, inner_depth)


# ─── Assignment tracking ───────────────────────────────────────────────────────

def _track_assignment(node: Node, source: bytes, analysis: FunctionAnalysis) -> None:
    """Track variable mutations from assignment nodes."""
    if node.child_count < 1:
        return
    lhs = node.children[0]
    var_name = _node_text(lhs, source)
    line = node.start_point[0] + 1
    if var_name not in analysis.variable_mutations:
        analysis.variable_mutations[var_name] = []
    analysis.variable_mutations[var_name].append(line)


# ─── Try/except analysis ──────────────────────────────────────────────────────

def _analyze_try_except(node: Node, source: bytes, analysis: FunctionAnalysis) -> None:
    """Analyze try/except blocks for caught exceptions and bare excepts."""
    for child in node.children:
        if child.type == "except_clause":
            # Check for bare except (no exception type specified)
            # except_clause children: 'except' [type] ['as' name] ':' block
            has_type = False
            for sub in child.children:
                if sub.type in ("identifier", "attribute", "as_pattern"):
                    has_type = True
                    if sub.type == "as_pattern":
                        # e.g., except ValueError as e
                        for part in sub.children:
                            if part.type in ("identifier", "attribute"):
                                exc_name = _node_text(part, source)
                                if exc_name not in ("as",):
                                    analysis.caught_exceptions.append(exc_name)
                                break
                    else:
                        analysis.caught_exceptions.append(_node_text(sub, source))
                    break
            if not has_type:
                analysis.has_bare_except = True


# ─── Call analysis ─────────────────────────────────────────────────────────────

def _analyze_call(node: Node, source: bytes, analysis: FunctionAnalysis) -> None:
    """Analyze a function call node for security concerns and call type."""
    if node.type != "call":
        return

    func_node = node.child_by_field_name("function")
    if not func_node:
        return

    call_name = _node_text(func_node, source)
    line = node.start_point[0] + 1

    # Track as external call
    analysis.external_calls.append(call_name)

    # Classify the call
    func_base = call_name.split(".")[-1] if "." in call_name else call_name

    # Database queries
    if func_base in DB_QUERY_PATTERNS:
        analysis.db_queries.append(f"{call_name} (line {line})")

    # File I/O
    if func_base in FILE_IO_PATTERNS or call_name == "open":
        analysis.file_operations.append(f"{call_name} (line {line})")

    # Network calls
    if func_base in NETWORK_CALL_PATTERNS:
        module = call_name.split(".")[0] if "." in call_name else ""
        if module in NETWORK_MODULES or func_base in ("urlopen", "fetch"):
            analysis.network_calls.append(f"{call_name} (line {line})")

    # Security-sensitive calls
    if func_base in DANGEROUS_FUNCTIONS or call_name in DANGEROUS_CALLS:
        analysis.security_sensitive_calls.append({
            "call": call_name,
            "line": line,
            "type": _classify_security_risk(call_name),
        })

    # Check for string formatting in arguments to DB/security calls
    if func_base in DB_QUERY_PATTERNS or func_base in DANGEROUS_FUNCTIONS:
        args_node = node.child_by_field_name("arguments")
        if args_node:
            _check_fstring_args(args_node, source, analysis, call_name, line)


def _classify_security_risk(call_name: str) -> str:
    """Classify the type of security risk for a call."""
    name = call_name.lower()
    if "eval" in name or "exec" in name or "compile" in name:
        return "code_execution"
    if "system" in name or "popen" in name or "subprocess" in name:
        return "command_injection"
    if "pickle" in name:
        return "insecure_deserialization"
    if "yaml.load" in name:
        return "insecure_deserialization"
    if "__import__" in name:
        return "dynamic_import"
    return "dangerous_call"


def _check_string_formatting_in_call(
    node: Node, source: bytes, analysis: FunctionAnalysis
) -> None:
    """Check if a function call uses f-strings or string formatting in args."""
    func_node = node.child_by_field_name("function")
    if not func_node:
        return

    call_name = _node_text(func_node, source)
    func_base = call_name.split(".")[-1] if "." in call_name else call_name

    # Only flag for DB and security-sensitive calls
    if func_base not in DB_QUERY_PATTERNS and func_base not in DANGEROUS_FUNCTIONS:
        return

    args_node = node.child_by_field_name("arguments")
    if not args_node:
        return

    # Look for f-strings or % formatting in arguments
    fstrings = _find_all_descendants(args_node, "interpolation")
    if fstrings:
        line = node.start_point[0] + 1
        analysis.security_sensitive_calls.append({
            "call": call_name,
            "line": line,
            "type": "string_interpolation_in_query",
            "detail": "f-string or format used in sensitive function argument",
        })


def _check_fstring_args(
    args_node: Node,
    source: bytes,
    analysis: FunctionAnalysis,
    call_name: str,
    line: int,
) -> None:
    """Check arguments of a call for f-string usage."""
    for arg in args_node.children:
        # Check for f-strings (formatted_string or string with interpolation)
        fstring_nodes = _find_all_descendants(arg, "interpolation")
        if fstring_nodes:
            # Only add if not already tracked
            existing = [
                s for s in analysis.security_sensitive_calls
                if s.get("line") == line and s.get("type") == "string_interpolation_in_query"
            ]
            if not existing:
                analysis.security_sensitive_calls.append({
                    "call": call_name,
                    "line": line,
                    "type": "string_interpolation_in_query",
                    "detail": "f-string interpolation in potentially sensitive call",
                })


# ─── Utility functions ─────────────────────────────────────────────────────────

def analyze_changed_functions(
    source_code: str,
    changed_lines: list[int],
    filename: str = "<unknown>",
) -> list[FunctionAnalysis]:
    """Analyze only the functions that overlap with changed lines.

    Useful for focusing review on modified code.

    Args:
        source_code: Full file source code.
        changed_lines: List of line numbers that were changed.
        filename: Name of the file.

    Returns:
        List of FunctionAnalysis for functions that overlap with changes.
    """
    file_analysis = analyze_python_file(source_code, filename)
    changed_set = set(changed_lines)

    changed_functions = []
    for func in file_analysis.all_functions:
        func_lines = set(range(func.start_line, func.end_line + 1))
        if func_lines & changed_set:
            changed_functions.append(func)

    return changed_functions


def get_function_at_line(
    source_code: str, line_number: int, filename: str = "<unknown>"
) -> FunctionAnalysis | None:
    """Get the function analysis for the function containing a specific line.

    Args:
        source_code: Full file source code.
        line_number: Line number to look up.
        filename: Name of the file.

    Returns:
        FunctionAnalysis if a function contains that line, None otherwise.
    """
    file_analysis = analyze_python_file(source_code, filename)

    for func in file_analysis.all_functions:
        if func.start_line <= line_number <= func.end_line:
            return func

    return None
