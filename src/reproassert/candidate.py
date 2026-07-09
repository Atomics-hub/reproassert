from __future__ import annotations

import ast
import hashlib
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from reproassert.errors import PolicyRejection

MAX_TEST_BYTES = 32 * 1024
MAX_EXPECTED_SYMPTOM_CHARS = 240
MAX_RATIONALE_CHARS = 1_000

_FORBIDDEN_IMPORT_ROOTS = {
    "ctypes",
    "ftplib",
    "httpx",
    "multiprocessing",
    "requests",
    "resource",
    "shutil",
    "smtplib",
    "socket",
    "subprocess",
    "telnetlib",
    "urllib",
}
_FORBIDDEN_CALLS = {
    "__import__",
    "breakpoint",
    "compile",
    "eval",
    "exec",
    "input",
    "open",
    "os._exit",
    "os.popen",
    "os.system",
    "print",
    "pytest.exit",
    "pytest.fail",
    "pytest.skip",
    "pytest.xfail",
    "sys.exit",
    "time.sleep",
}
_DANGEROUS_OS_IMPORTS = {"_exit", "popen", "system"}
_RUNNER_IMPORT_ROOTS = {
    "_pytest",
    "iniconfig",
    "packaging",
    "pluggy",
    "pygments",
    "pytest",
}
_SAFE_ANNOTATION_NAMES = {
    "bool",
    "bytes",
    "dict",
    "float",
    "int",
    "list",
    "set",
    "str",
    "tuple",
}
_TERMINAL_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class ValidatedCandidate:
    test_content: str
    test_function: str
    expected_symptom: str
    rationale: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.test_content.encode("utf-8")).hexdigest()


def candidate_path(issue_number: int) -> str:
    if issue_number < 1:
        raise PolicyRejection("invalid_issue_number", "Issue number must be positive.")
    return f"tests/reproassert/test_issue_{issue_number}.py"


def candidate_function(issue_number: int) -> str:
    if issue_number < 1:
        raise PolicyRejection("invalid_issue_number", "Issue number must be positive.")
    return f"test_issue_{issue_number}_reproduction"


def validate_candidate_payload(
    payload: Mapping[str, Any], *, issue_number: int
) -> ValidatedCandidate:
    required = {"test_content", "expected_symptom", "rationale"}
    if set(payload) != required:
        raise PolicyRejection(
            "candidate_schema",
            "Generator output must contain exactly test_content, expected_symptom, and rationale.",
        )

    content = payload["test_content"]
    expected = payload["expected_symptom"]
    rationale = payload["rationale"]
    if (
        not isinstance(content, str)
        or not isinstance(expected, str)
        or not isinstance(rationale, str)
    ):
        raise PolicyRejection("candidate_schema", "Every generator output field must be text.")

    encoded = content.encode("utf-8")
    if not encoded or len(encoded) > MAX_TEST_BYTES or "\x00" in content:
        raise PolicyRejection(
            "candidate_size", f"Candidate test must be 1-{MAX_TEST_BYTES} UTF-8 bytes."
        )
    if not content.endswith("\n"):
        content += "\n"

    expected = _bounded_plain_text(
        expected,
        name="expected_symptom",
        minimum=3,
        maximum=MAX_EXPECTED_SYMPTOM_CHARS,
        single_line=True,
    )
    rationale = _bounded_plain_text(
        rationale,
        name="rationale",
        minimum=1,
        maximum=MAX_RATIONALE_CHARS,
        single_line=False,
    )

    test_function = candidate_function(issue_number)
    _validate_python(content, test_function, expected)
    return ValidatedCandidate(content, test_function, expected, rationale)


def render_new_file_patch(relative_path: str, content: str) -> str:
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise PolicyRejection("candidate_path", "Candidate path must stay inside the source tree.")
    normalized = path.as_posix()
    if not normalized.startswith("tests/reproassert/") or not normalized.endswith(".py"):
        raise PolicyRejection("candidate_path", "Candidate path is not controller-approved.")

    if not content.endswith("\n"):
        content += "\n"
    lines = content.splitlines()
    body = "\n".join(f"+{line}" for line in lines)
    return (
        f"diff --git a/{normalized} b/{normalized}\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        f"+++ b/{normalized}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{body}\n"
    )


def _validate_python(content: str, expected_function: str, expected_symptom: str) -> None:
    try:
        tree = ast.parse(content, filename="<reproassert-candidate>", mode="exec")
        compile(tree, "<reproassert-candidate>", "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as exc:
        raise PolicyRejection(
            "candidate_syntax", f"Candidate test does not compile: {exc}"
        ) from exc

    functions = [
        node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if len(functions) != 1 or functions[0].name != expected_function:
        raise PolicyRejection(
            "candidate_test_count",
            f"Candidate must define only one function: {expected_function}.",
        )
    test_function = functions[0]
    if isinstance(test_function, ast.AsyncFunctionDef):
        raise PolicyRejection(
            "candidate_async", "Async tests are outside the strict Python profile."
        )
    if any(isinstance(node, (ast.ClassDef, ast.Lambda)) for node in ast.walk(tree)):
        raise PolicyRejection(
            "candidate_test_count", "Candidate helpers and classes are outside the strict profile."
        )

    for statement in tree.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)):
            continue
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            if _is_safe_literal_assignment(statement):
                continue
            raise PolicyRejection(
                "candidate_top_level_execution",
                "Top-level assignments must contain only literal test data.",
            )
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        raise PolicyRejection(
            "candidate_top_level_execution",
            "Candidate may not execute code at module import time.",
        )

    import_aliases = _import_aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            if any(module.split(".", 1)[0] in _FORBIDDEN_IMPORT_ROOTS for module in modules):
                raise PolicyRejection(
                    "candidate_forbidden_import",
                    "Candidate imports a module blocked by strict policy.",
                )
            if (
                isinstance(node, ast.ImportFrom)
                and (node.module or "") == "os"
                and any(alias.name in _DANGEROUS_OS_IMPORTS for alias in node.names)
            ):
                raise PolicyRejection(
                    "candidate_forbidden_import",
                    "Candidate imports a process primitive blocked by strict policy.",
                )
        if (
            isinstance(node, ast.Assert)
            and isinstance(node.test, ast.Constant)
            and not node.test.value
        ):
            raise PolicyRejection(
                "candidate_assert_false", "Unconditional failing assertions are rejected."
            )
        if isinstance(node, ast.Raise):
            raise PolicyRejection(
                "candidate_explicit_raise", "Explicit raise statements are rejected."
            )
        if isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and node.test.value:
            raise PolicyRejection("candidate_infinite_loop", "Obvious infinite loops are rejected.")
        if isinstance(node, ast.Call):
            call_name = _resolved_call_name(node.func, import_aliases)
            if call_name in _FORBIDDEN_CALLS or any(
                call_name.startswith(f"{root}.") for root in _FORBIDDEN_IMPORT_ROOTS
            ):
                raise PolicyRejection(
                    "candidate_forbidden_call",
                    f"Candidate call is blocked by strict policy: {call_name}",
                )
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                name = _call_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
                if name.startswith("pytest.mark.skip") or name.startswith("pytest.mark.xfail"):
                    raise PolicyRejection(
                        "candidate_skip_marker", "Skip and xfail markers are not reproductions."
                    )

    _validate_assertion_contract(
        test_function,
        import_aliases=import_aliases,
        expected_symptom=expected_symptom,
    )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                bound_name = imported.asname or imported.name.split(".", 1)[0]
                aliases[bound_name] = imported.name if imported.asname else bound_name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                bound_name = imported.asname or imported.name
                aliases[bound_name] = f"{module}.{imported.name}" if module else imported.name
    return aliases


def _resolved_call_name(node: ast.AST, aliases: Mapping[str, str]) -> str:
    name = _call_name(node)
    if not name:
        return ""
    first, separator, remainder = name.partition(".")
    resolved = aliases.get(first)
    if resolved is None:
        return name
    return f"{resolved}.{remainder}" if separator else resolved


def _validate_assertion_contract(
    test_function: ast.FunctionDef,
    *,
    import_aliases: Mapping[str, str],
    expected_symptom: str,
) -> None:
    if (
        test_function.decorator_list
        or test_function.args.defaults
        or any(default is not None for default in test_function.args.kw_defaults)
    ):
        raise PolicyRejection(
            "candidate_test_shape",
            "Strict tests may not use decorators or executable default arguments.",
        )
    if test_function.args.vararg or test_function.args.kwarg:
        raise PolicyRejection(
            "candidate_test_shape", "Strict tests may use only explicit pytest fixture arguments."
        )

    behavior_sources = {
        alias
        for alias, resolved in import_aliases.items()
        if resolved.split(".", 1)[0] not in sys.stdlib_module_names | _RUNNER_IMPORT_ROOTS
    }
    statements = list(test_function.body)
    if statements and _is_docstring_statement(statements[0]):
        statements = statements[1:]
    assertions = [statement for statement in statements if isinstance(statement, ast.Assert)]
    if len(assertions) != 1 or not statements or statements[-1] is not assertions[0]:
        raise PolicyRejection(
            "candidate_assertion_required",
            "Strict candidates require exactly one final assertion.",
        )

    tainted_names: set[str] = set()
    for statement in statements[:-1]:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            raise PolicyRejection(
                "candidate_test_shape",
                "Strict tests use a linear sequence of assignments followed by one assertion.",
            )
        value = statement.value
        if value is None:
            raise PolicyRejection("candidate_test_shape", "Assignments must have a value.")
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        assigned_names = {name for target in targets for name in _assignment_names(target)}
        tainted_names.difference_update(assigned_names)
        if _is_behavior_value(
            value,
            behavior_sources=behavior_sources,
            tainted_names=tainted_names,
        ):
            tainted_names.update(assigned_names)

    assertion = assertions[0]
    if not _is_behavior_predicate(
        assertion.test,
        behavior_sources=behavior_sources,
        tainted_names=tainted_names,
    ):
        raise PolicyRejection(
            "candidate_unconditional_assert",
            "The assertion truth value must derive directly from an executed project call.",
        )
    if not (
        isinstance(assertion.msg, ast.Constant)
        and isinstance(assertion.msg.value, str)
        and expected_symptom.casefold() in assertion.msg.value.casefold()
    ):
        raise PolicyRejection(
            "candidate_symptom_marker",
            "expected_symptom must appear in a literal assertion message.",
        )


def _is_behavior_predicate(
    node: ast.AST,
    *,
    behavior_sources: set[str],
    tainted_names: set[str],
) -> bool:
    if _is_behavior_value(
        node,
        behavior_sources=behavior_sources,
        tainted_names=tainted_names,
    ):
        return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_behavior_value(
            node.operand,
            behavior_sources=behavior_sources,
            tainted_names=tainted_names,
        )
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        return _is_behavior_value(
            node.left,
            behavior_sources=behavior_sources,
            tainted_names=tainted_names,
        ) or _is_behavior_value(
            node.comparators[0],
            behavior_sources=behavior_sources,
            tainted_names=tainted_names,
        )
    return False


def _is_behavior_value(
    node: ast.AST,
    *,
    behavior_sources: set[str],
    tainted_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted_names
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _is_behavior_value(
            node.value,
            behavior_sources=behavior_sources,
            tainted_names=tainted_names,
        )
    if not isinstance(node, ast.Call):
        return False
    function = node.func
    if isinstance(function, ast.Name):
        return function.id in behavior_sources or function.id in tainted_names
    if isinstance(function, (ast.Attribute, ast.Subscript)):
        return _is_behavior_root(
            function.value,
            behavior_sources=behavior_sources,
            tainted_names=tainted_names,
        )
    return False


def _is_behavior_root(
    node: ast.AST,
    *,
    behavior_sources: set[str],
    tainted_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in behavior_sources or node.id in tainted_names
    return _is_behavior_value(
        node,
        behavior_sources=behavior_sources,
        tainted_names=tainted_names,
    )


def _is_docstring_statement(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _assignment_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.List, ast.Tuple)):
        return tuple(name for element in node.elts for name in _assignment_names(element))
    return ()


def _is_safe_literal_assignment(statement: ast.Assign | ast.AnnAssign) -> bool:
    value: ast.expr
    if isinstance(statement, ast.Assign):
        targets = statement.targets
        value = statement.value
    else:
        targets = [statement.target]
        if statement.value is None:
            return False
        value = statement.value
        if not _is_safe_annotation(statement.annotation):
            return False
    if not all(_is_safe_assignment_target(target) for target in targets):
        return False
    try:
        ast.literal_eval(value)
    except (TypeError, ValueError):
        return False
    return True


def _is_safe_assignment_target(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return bool(node.elts) and all(_is_safe_assignment_target(element) for element in node.elts)
    return False


def _is_safe_annotation(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _SAFE_ANNOTATION_NAMES
    if isinstance(node, ast.Subscript):
        return _is_safe_annotation(node.value) and _is_safe_annotation(node.slice)
    if isinstance(node, ast.Tuple):
        return all(_is_safe_annotation(element) for element in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_safe_annotation(node.left) and _is_safe_annotation(node.right)
    if isinstance(node, ast.Constant):
        return node.value is None or node.value is Ellipsis
    return False


def _bounded_plain_text(
    value: str, *, name: str, minimum: int, maximum: int, single_line: bool
) -> str:
    normalized = value.strip()
    if len(normalized) < minimum or len(normalized) > maximum:
        raise PolicyRejection("candidate_schema", f"{name} must be {minimum}-{maximum} characters.")
    if _TERMINAL_CONTROL.search(normalized) or (single_line and "\n" in normalized):
        raise PolicyRejection("candidate_schema", f"{name} contains unsafe control text.")
    return normalized
