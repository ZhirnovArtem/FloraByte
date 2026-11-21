"""General Kotlin / Spring Boot static & cross-file semantic rules (no project-specific hardcoding)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ..context import FileContext

Hit = tuple[int, int, str, str]

_SQL_CALL_RE = re.compile(
    r"""\b[A-Za-z_]\w*\.(?:query(?:ForList|ForObject|ForMap|ForRowSet|ForStream)?|update|execute|batchUpdate|createNativeQuery|createSQLQuery)\s*\("""
)
_STRING_INTERP_RE = re.compile(r"""(?<!\\)\$(?:\{[A-Za-z_][^}]*\}|[A-Za-z_]\w*)""")
_OWNER_COL_RE = re.compile(r"""\b(customer_id|user_id|owner_id|account_id|client_id|tenant_id)\b""", re.IGNORECASE)


def _line_col(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    col = pos - (text.rfind("\n", 0, pos) + 1) + 1
    return line, col


def _extract_balanced_call(text: str, open_paren_pos: int, max_chars: int = 800) -> str:
    depth = 0
    in_str = False
    escaped = False
    end = min(len(text), open_paren_pos + max_chars)
    for i in range(open_paren_pos, end):
        ch = text[i]
        if in_str:
            if ch == "\\" and not escaped:
                escaped = True
            elif ch == '"' and not escaped:
                in_str = False
            else:
                escaped = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_pos : i + 1]
    return text[open_paren_pos:end]


def detect_sql_injection(ctx: FileContext) -> list[Hit]:
    code = ctx.code
    out: list[Hit] = []
    # Collect local SQL-like variables built via interpolation or concatenation
    tainted_sql_vars: set[str] = set()
    for m in re.finditer(
        r"""\b(?:val|var)\s+([A-Za-z_]\w*)\s*=\s*(?:"""
        r"""\"[^\"]*(?:\$\{?[A-Za-z_]\w*\}?)[^\"]*\""""
        r"""|\"[^\"]*\"\s*\+\s*[A-Za-z_]\w*"""
        r"""|String\.format\s*\([^)]*\))""",
        code,
    ):
        tainted_sql_vars.add(m.group(1))

    for m in _SQL_CALL_RE.finditer(code):
        open_idx = m.end() - 1
        args = _extract_balanced_call(code, open_idx)
        # First string literal in call or string concatenation / String.format / tainted variable
        has_interp_literal = bool(
            re.search(r'"""[\s\S]*?(?<!\\)\$(?:\{[A-Za-z_][^}]*\}|[A-Za-z_]\w*)[\s\S]*?"""', args)
            or re.search(r'"[^"\n]*(?<!\\)\$(?:\{[A-Za-z_][^}]*\}|[A-Za-z_]\w*)[^"\n]*"', args)
        )
        has_concat = bool(re.search(r'"[^"\n]*"\s*\+\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*\+\s*"[^"\n]*"', args))
        has_format = "String.format(" in args
        uses_tainted_var = any(re.search(rf"\(\s*{re.escape(v)}\b", args) for v in tainted_sql_vars)

        if has_interp_literal or has_concat or has_format or uses_tainted_var:
            line, col = _line_col(code, m.start())
            snippet = (m.group(0) + args[1:]).splitlines()[0][:160]
            out.append((line, col, snippet, "SQL-запрос формируется строковой интерполяцией или конкатенацией."))
    return out


def detect_tls_verification(ctx: FileContext) -> list[Hit]:
    code = ctx.code
    out: list[Hit] = []
    patterns = [
        re.compile(r"""HostnameVerifier\s*(?:\([^)]*\))?\s*\{[^}]{0,120}->\s*true\b""", re.S),
        re.compile(r"""override\s+fun\s+verify\s*\([^)]*\)\s*(?::\s*Boolean\s*)?(?:=\s*true\b|\{[^}]{0,120}\breturn\s+true\b)""", re.S),
        re.compile(r"""\b(?:NoopHostnameVerifier|TrustAllStrategy)\b"""),
        re.compile(r"""override\s+fun\s+check(?:Client|Server)Trusted\s*\([^)]*\)\s*\{\s*\}""", re.S),
    ]
    seen_lines: set[int] = set()
    for pat in patterns:
        for m in pat.finditer(code):
            line, col = _line_col(code, m.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            snippet = m.group(0).splitlines()[0][:160]
            out.append((line, col, snippet, "Отключена проверка TLS-сертификата или имени хоста (безусловное доверие)."))
    return out


def detect_cors_wildcard(ctx: FileContext) -> list[Hit]:
    code = ctx.code
    out: list[Hit] = []
    patterns = [
        re.compile(r"""(?:allowedOrigins|addAllowedOrigin|allowedOriginPatterns?|addAllowedOriginPattern)\s*\([^)]*"\*"[^)]*\)""", re.I | re.S),
        re.compile(r"""(?:allowedOrigins|allowedOriginPatterns?)\s*=\s*(?:listOf|mutableListOf|setOf|arrayOf)\s*\([^)]*"\*"[^)]*\)""", re.I | re.S),
        re.compile(r"""@CrossOrigin\s*\([^)]*origins\s*=\s*\[?\s*"\*"[^)]*\)""", re.I | re.S),
    ]
    seen_lines: set[int] = set()
    has_creds = bool(re.search(r"""allowCredentials\s*(?:=\s*true|\(\s*true\s*\)|=\s*"true")""", code, re.I))
    for pat in patterns:
        for m in pat.finditer(code):
            line, col = _line_col(code, m.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            snippet = m.group(0).splitlines()[0][:160]
            rationale = (
                "Разрешён wildcard origin '*' совместно с allowCredentials=true."
                if has_creds
                else "Разрешён wildcard origin '*' в настройках CORS."
            )
            out.append((line, col, snippet, rationale))
    return out


@dataclass
class _ControllerHandler:
    path: str
    method: str | None
    body: str
    has_auth: bool
    has_db_access: bool


def _normalize_route(prefix: str, suffix: str) -> str:
    p = "/" + "/".join(x for x in (prefix.strip("/") + "/" + suffix.strip("/")).split("/") if x)
    return p if p else "/"


def _collect_controllers(contexts: tuple[FileContext, ...]) -> list[_ControllerHandler]:
    handlers: list[_ControllerHandler] = []
    for c in contexts:
        code = c.code
        if "@RestController" not in code and "@Controller" not in code:
            continue
        cls_prefix = ""
        m_cls = re.search(r"""@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?["']([^"']+)["']""", code)
        if m_cls and m_cls.start() < (code.find("class ") if "class " in code else len(code)):
            cls_prefix = m_cls.group(1)

        map_re = re.compile(
            r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["'][^)]*\)\s*fun\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"""
        )
        matches = list(map_re.finditer(code))
        for idx, m in enumerate(matches):
            ann, sub_path, _fn, params = m.groups()
            http_m = None if ann == "RequestMapping" else ann.replace("Mapping", "").upper()
            full_path = _normalize_route(cls_prefix, sub_path)
            end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(code)
            tail = code[m.end() : min(end_pos, m.end() + 1000)]
            next_marker = re.search(r"\n\s*(?:@|\bfun\s+|\bclass\s+)", tail)
            body = tail[: next_marker.start()] if next_marker else tail
            has_auth = bool(
                re.search(r"@PreAuthorize|@Secured|@RolesAllowed|Principal\b|Authentication\b|@AuthenticationPrincipal|SecurityContextHolder", params + " " + body)
            )
            has_db = bool(
                re.search(r"\b(?:jdbc|jdbcTemplate|entityManager|repository|reader|dao)\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b", body, re.I)
            )
            handlers.append(_ControllerHandler(full_path, http_m, body, has_auth, has_db))
    return handlers


def _route_matches_prefix(route: str, prefix_pattern: str) -> bool:
    if prefix_pattern.endswith("/**"):
        base = prefix_pattern[:-3].rstrip("/")
        return route == base or route.startswith(base + "/")
    return route == prefix_pattern


def detect_route_authorization(ctx: FileContext) -> list[Hit]:
    code = ctx.code
    out: list[Hit] = []
    seen_lines: set[int] = set()

    # 1) Broad anyRequest().permitAll()
    for m in re.finditer(r"""anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)""", code):
        line, col = _line_col(code, m.start())
        seen_lines.add(line)
        out.append((line, col, m.group(0), "anyRequest().permitAll() открывает доступ ко всем маршрутам."))

    # Collect protected requestMatchers prefixes in the same security file
    protected_prefixes: list[str] = []
    for m in re.finditer(
        r"""requestMatchers\s*\(\s*(?:(?:GET|POST|PUT|DELETE|PATCH|HttpMethod\.\w+)\s*,\s*)?["']([^"']+)["']\s*\)\s*\.\s*(?:hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|authenticated)\b""",
        code,
    ):
        protected_prefixes.append(m.group(1))

    controllers = _collect_controllers(ctx.project_contexts) if ctx.project_contexts else []

    # 2) Specific requestMatchers(...).permitAll()
    for m in re.finditer(
        r"""requestMatchers\s*\(\s*(?:(?:GET|POST|PUT|DELETE|PATCH|HttpMethod\.\w+)\s*,\s*)?["']([^"']+)["']\s*\)\s*\.\s*permitAll\s*\(\s*\)""",
        code,
    ):
        pattern = m.group(1)
        line, col = _line_col(code, m.start())
        if line in seen_lines:
            continue

        is_sensitive_prefix = bool(re.search(r"""(?:/admin|/actuator|/manage|/internal|/console)""", pattern, re.I))
        shadows_protected = any(_route_matches_prefix(pattern, p) and p != pattern for p in protected_prefixes)
        matching_handlers = [h for h in controllers if _route_matches_prefix(h.path, pattern)]
        exposes_db_without_auth = any(h.has_db_access and not h.has_auth for h in matching_handlers)
        is_broad_api_wildcard = pattern.startswith("/api/") and "**" in pattern

        if is_sensitive_prefix or shadows_protected or exposes_db_without_auth or is_broad_api_wildcard:
            seen_lines.add(line)
            out.append((
                line,
                col,
                m.group(0),
                f"Маршрут {pattern} открыт через permitAll(), хотя пересекается с защищённой зоной или отдаёт данные без проверки прав.",
            ))
    return out


def detect_object_authorization(ctx: FileContext) -> list[Hit]:
    """Detect missing object-level authorization (IDOR/BOLA) across repository & controller methods."""
    code = ctx.code
    out: list[Hit] = []
    if not ctx.project_contexts:
        return out

    # Find unauthenticated controller endpoints accepting an object ID via @PathVariable/@RequestParam
    # and calling a method on an injected bean/field.
    unauth_calls: set[tuple[str, str]] = set()  # (callee_method_name, controller_rel_path)
    for c in ctx.project_contexts:
        cc = c.code
        if "@RestController" not in cc and "@Controller" not in cc:
            continue
        map_re = re.compile(
            r"""@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\([^)]*\)\s*fun\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"""
        )
        matches = list(map_re.finditer(cc))
        for idx, m in enumerate(matches):
            _fn, params = m.groups()
            end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(cc)
            tail = cc[m.end() : min(end_pos, m.end() + 1000)]
            next_marker = re.search(r"\n\s*(?:@|\bfun\s+|\bclass\s+)", tail)
            body = tail[: next_marker.start()] if next_marker else tail
            if not re.search(r"@PathVariable|@RequestParam", params):
                continue
            has_auth = bool(
                re.search(r"Principal\b|Authentication\b|@AuthenticationPrincipal|SecurityContextHolder|@PreAuthorize", params + " " + body)
            )
            if has_auth:
                continue
            for call in re.finditer(r"\b([a-zA-Z_]\w*)\.([a-zA-Z_]\w*)\s*\(\s*([a-zA-Z_]\w*)\s*\)", body):
                method_name = call.group(2)
                arg_name = call.group(3)
                if re.search(rf"\b{re.escape(arg_name)}\b", params):
                    unauth_calls.add((method_name, c.rel_path))

    if not unauth_calls and "@Repository" not in code:
        return out

    # Inspect methods in current file that run single-ID SQL queries on tables with an owner column
    has_owner_concept_in_file = bool(_OWNER_COL_RE.search(code))
    if not has_owner_concept_in_file:
        return out

    fn_re = re.compile(r"""fun\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*:\s*[^,)]+\)""")
    fn_matches = list(fn_re.finditer(code))
    for idx, fm in enumerate(fn_matches):
        fn_name, _id_param = fm.groups()
        end_pos = fn_matches[idx + 1].start() if idx + 1 < len(fn_matches) else len(code)
        fn_tail = code[fm.end() : min(end_pos, fm.end() + 1200)]
        next_fn = re.search(r"\n\s*(?:@[\w]+\s*\n\s*)?(?:fun|class)\s+", fn_tail)
        fn_body = fn_tail[: next_fn.start()] if next_fn else fn_tail
        if not re.search(r"\bSELECT\b", fn_body, re.I):
            continue
        # Must filter by a single predicate without owner column in WHERE
        sql_m = re.search(r'"([^"]*\bSELECT\b[^"]*\bWHERE\b[^"]*)"', fn_body, re.I | re.S)
        if not sql_m:
            continue
        sql_text = sql_m.group(1)
        where_part = re.split(r"\bWHERE\b", sql_text, flags=re.I)[-1]
        if _OWNER_COL_RE.search(where_part):
            continue
        # Either the SELECT exposes an owner column or file models an owner column AND an unauth controller calls it
        exposes_owner = bool(_OWNER_COL_RE.search(sql_text))
        called_without_auth = any(m_name == fn_name for m_name, _ in unauth_calls)
        if exposes_owner and (called_without_auth or not ctx.project_contexts):
            # Point to the SQL call / query line
            sql_call_m = _SQL_CALL_RE.search(fn_body)
            abs_pos = fm.end() + (sql_call_m.start() if sql_call_m else sql_m.start())
            line, col = _line_col(code, abs_pos)
            out.append((
                line,
                col,
                sql_text.strip()[:160],
                f"Метод {fn_name} загружает запись только по идентификатору без проверки владельца (IDOR/BOLA).",
            ))
    return out
