"""Isolated sandbox for user-defined Custom Node logic (AST guard + isolated subprocess worker)."""

from __future__ import annotations

import ast
import asyncio
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.masking import redact_text
from app.core.models import Finding

SAFE_STDLIB_MODULES = frozenset(
    {
        "base64",
        "collections",
        "datetime",
        "decimal",
        "functools",
        "hashlib",
        "hmac",
        "itertools",
        "json",
        "math",
        "re",
        "statistics",
        "string",
        "typing",
    }
)

FORBIDDEN_CALL_NAMES = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "delattr",
        "dir",
        "eval",
        "exec",
        "exit",
        "getattr",
        "globals",
        "help",
        "input",
        "locals",
        "memoryview",
        "open",
        "quit",
        "setattr",
        "vars",
    }
)

MAX_CODE_CHARS = 32_000
MAX_STDOUT_CHARS = 32_000
DEFAULT_SANDBOX_TIMEOUT_SEC = 5.0
MAX_MEMORY_BYTES = 256 * 1024 * 1024


@dataclass
class CodeValidationResult:
    ok: bool
    errors: list[str]
    warnings: list[str]
    is_async: bool = False


class _SecurityAstVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.has_run = False
        self.run_is_async = False

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            if root not in SAFE_STDLIB_MODULES:
                self.errors.append(
                    f"Запрещённый импорт '{alias.name}' (строка {node.lineno}). "
                    f"Разрешены только безопасные модули обработки данных: {', '.join(sorted(SAFE_STDLIB_MODULES))}."
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.level and node.level > 0:
            self.errors.append(f"Относительный импорт запрещён (строка {node.lineno}).")
            return
        mod = (node.module or "").split(".", 1)[0]
        if mod not in SAFE_STDLIB_MODULES:
            self.errors.append(
                f"Запрещённый импорт из '{node.module}' (строка {node.lineno}). "
                f"Разрешены только безопасные модули: {', '.join(sorted(SAFE_STDLIB_MODULES))}."
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        if node.attr.startswith("__"):
            self.errors.append(
                f"Запрещённый доступ к служебному атрибуту '{node.attr}' (строка {node.lineno})."
            )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> Any:
        if node.id.startswith("__") and node.id not in ("__name__",):
            self.errors.append(
                f"Запрещённое обращение к внутреннему идентификатору '{node.id}' (строка {node.lineno})."
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_CALL_NAMES:
                self.errors.append(
                    f"Запрещённый вызов '{node.func.id}()' (строка {node.lineno})."
                )
            elif node.func.id == "type" and len(node.args) >= 3:
                self.errors.append(
                    f"Динамическое создание классов через type(..., ..., ...) запрещено (строка {node.lineno})."
                )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if node.name == "run":
            self.has_run = True
            self.run_is_async = False
            self._check_run_signature(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        if node.name == "run":
            self.has_run = True
            self.run_is_async = True
            self._check_run_signature(node)
        self.generic_visit(node)

    def _check_run_signature(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        argc = len(node.args.posonlyargs) + len(node.args.args)
        if argc < 2 or argc > 3:
            self.errors.append(
                f"Функция run(...) должна принимать 2 или 3 аргумента (например: async def run(ctx, inputs, params):), получено {argc}."
            )


def validate_custom_node_code(code: str) -> CodeValidationResult:
    """Perform syntax + AST security verification on user custom node code."""
    src = (code or "").strip()
    if not src:
        return CodeValidationResult(ok=False, errors=["Код ноды не может быть пустым."], warnings=[])
    if len(src) > MAX_CODE_CHARS:
        return CodeValidationResult(
            ok=False,
            errors=[f"Размер кода превышает предел ({MAX_CODE_CHARS} символов)."],
            warnings=[],
        )
    try:
        tree = ast.parse(src, filename="<custom_node>", mode="exec")
    except SyntaxError as exc:
        return CodeValidationResult(
            ok=False,
            errors=[f"Синтаксическая ошибка (строка {exc.lineno}, позиция {exc.offset}): {exc.msg}"],
            warnings=[],
        )

    visitor = _SecurityAstVisitor()
    visitor.visit(tree)
    if not visitor.has_run:
        visitor.errors.append("Код должен определять точку входа: async def run(ctx, inputs, params) или def run(ctx, inputs, params).")

    return CodeValidationResult(
        ok=len(visitor.errors) == 0,
        errors=visitor.errors,
        warnings=visitor.warnings,
        is_async=visitor.run_is_async,
    )


def _to_json_safe(value: Any) -> Any:
    if isinstance(value, Finding):
        return value.to_submission()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


_SANDBOX_BOOTSTRAP = r'''
import asyncio
import inspect
import json
import sys

try:
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    except Exception:
        pass
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        limit = 256 * 1024 * 1024
        if hard == resource.RLIM_INFINITY or hard >= limit:
            resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
    except Exception:
        pass
except Exception:
    pass

ALLOWED_MODULES = {
    "base64", "collections", "datetime", "decimal", "functools",
    "hashlib", "hmac", "itertools", "json", "math", "re",
    "statistics", "string", "typing",
}

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level != 0:
        raise ImportError("Relative imports are forbidden")
    root = name.split(".", 1)[0]
    if root not in ALLOWED_MODULES:
        raise ImportError(f"Module '{name}' is not allowed in sandbox")
    return __import__(name, globals, locals, fromlist, 0)

_logs = []
def _safe_print(*args, **kwargs):
    if len(_logs) < 50:
        _logs.append(" ".join(str(a) for a in args)[:300])

SAFE_BUILTINS = {
    "__import__": _safe_import,
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "Exception": Exception,
    "filter": filter,
    "float": float,
    "int": int,
    "isinstance": isinstance,
    "KeyError": KeyError,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "print": _safe_print,
    "range": range,
    "round": round,
    "RuntimeError": RuntimeError,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "TypeError": TypeError,
    "ValueError": ValueError,
    "zip": zip,
}

payload = json.loads(sys.stdin.read())
code = payload["code"]
ctx = payload["ctx"]
inputs = payload["inputs"]
params = payload["params"]

ns = {"__builtins__": SAFE_BUILTINS, "__name__": "__custom_node__"}
exec(compile(code, "<custom_node>", "exec"), ns, ns)
fn = ns.get("run")
if not callable(fn):
    raise RuntimeError("Entrypoint run(ctx, inputs, params) is missing")

sig_argc = len(inspect.signature(fn).parameters)
args = (ctx, inputs) if sig_argc == 2 else (ctx, inputs, params)

if inspect.iscoroutinefunction(fn):
    result = asyncio.run(fn(*args))
else:
    result = fn(*args)

sys.stdout.write(json.dumps({"ok": True, "result": result, "logs": _logs}, ensure_ascii=False))
'''


async def execute_custom_node_sandboxed(
    *,
    code: str,
    ctx_info: dict[str, Any],
    inputs: dict[str, Any],
    params: dict[str, Any],
    outputs_spec: list[dict[str, Any]] | None = None,
    timeout_sec: float = DEFAULT_SANDBOX_TIMEOUT_SEC,
) -> tuple[dict[str, Any], list[str]]:
    """Run custom node logic in an isolated subprocess with strict env/fs/time/AST restrictions."""
    validation = validate_custom_node_code(code)
    if not validation.ok:
        raise RuntimeError("Ошибка проверки кода пользовательской ноды: " + "; ".join(validation.errors))

    safe_payload = {
        "code": code,
        "ctx": _to_json_safe(ctx_info),
        "inputs": _to_json_safe(inputs),
        "params": _to_json_safe(params),
    }
    stdin_bytes = json.dumps(safe_payload, ensure_ascii=False).encode("utf-8")

    with tempfile.TemporaryDirectory(prefix="fb_sandbox_") as empty_dir:
        clean_env = {
            "PATH": "",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-c",
            _SANDBOX_BOOTSTRAP,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=empty_dir,
            env=clean_env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(stdin_bytes), timeout=timeout_sec)
        except asyncio.TimeoutError as exc:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            raise RuntimeError(f"Превышен лимит времени выполнения пользовательской ноды ({timeout_sec:.0f}с).") from exc

    if proc.returncode != 0:
        err_msg = redact_text(stderr.decode("utf-8", errors="replace").strip())
        raise RuntimeError(f"Ошибка выполнения пользовательской ноды: {err_msg or f'exit={proc.returncode}'}")

    raw_out = stdout.decode("utf-8", errors="replace")
    if len(raw_out) > MAX_STDOUT_CHARS * 4:
        raise RuntimeError("Результат пользовательской ноды превышает допустимый размер вывода.")

    try:
        parsed = json.loads(raw_out)
    except Exception as exc:
        raise RuntimeError("Пользовательская нода вернула некорректный JSON-ответ.") from exc

    result = parsed.get("result")
    logs = parsed.get("logs") if isinstance(parsed.get("logs"), list) else []
    if not isinstance(result, dict):
        raise RuntimeError("Функция run(...) должна возвращать словарь dict (например: {'result': ...}).")

    # Validate output schema / hydrate Findings ports when declared
    spec_by_name = {
        str(p.get("name")): str(p.get("kind") or "Any")
        for p in (outputs_spec or [])
        if isinstance(p, dict) and p.get("name")
    }
    if spec_by_name:
        if not any(k in result for k in spec_by_name):
            expected = ", ".join(spec_by_name.keys())
            raise RuntimeError(
                f"Выходной словарь ноды не содержит объявленных портов ({expected}). Получено: {list(result.keys())}"
            )
        for port_name, port_kind in spec_by_name.items():
            if port_kind == "Findings" and port_name in result:
                raw_items = result[port_name]
                if not isinstance(raw_items, list):
                    raise RuntimeError(f"Выходной порт '{port_name}' (Findings) должен быть списком.")
                hydrated: list[Finding] = []
                for idx, item in enumerate(raw_items):
                    if isinstance(item, Finding):
                        hydrated.append(item)
                    elif isinstance(item, dict):
                        try:
                            hydrated.append(Finding.model_validate(item))
                        except Exception as exc:
                            raise RuntimeError(f"Некорректный Finding в порту '{port_name}[{idx}]': {exc}") from exc
                    else:
                        raise RuntimeError(f"Элемент '{port_name}[{idx}]' должен быть словарём Finding.")
                result[port_name] = hydrated

    return result, [redact_text(str(x)) for x in logs]
