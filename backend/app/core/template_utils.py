"""Template visibility ACLs, email masking, and graph secret sanitization."""

from __future__ import annotations

import copy
import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.core.masking import redact_text
from app.core.models import Workflow

VALID_TEMPLATE_VISIBILITIES = {"private", "public"}

_SENSITIVE_PARAM_KEYS = {
    "bot_token",
    "api_key",
    "password",
    "access_token",
    "secret",
    "token",
    "private_key",
    "auth_token",
    "credential_id",
}

_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "x-api-key",
    "proxy-authorization",
    "cookie",
    "x-auth-token",
}

_SENSITIVE_QUERY_KEYS = {
    "token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "access_token",
    "auth",
}


def mask_author_email(email: str | None) -> str:
    if not email or "@" not in email:
        return ""
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    elif len(local) <= 3:
        masked_local = local[0] + "**"
    else:
        masked_local = local[0] + "***" + local[-1]
    return f"{masked_local}@{domain}"


def can_view_template(w: Workflow, user_id: str | None) -> bool:
    if not w.is_template:
        return False
    if w.owner_id is None:
        return True
    if (w.visibility or "private") == "public":
        return True
    if user_id is not None and w.owner_id == user_id:
        return True
    return False


def can_edit_template(w: Workflow, user_id: str | None) -> bool:
    if not w.is_template:
        return False
    if w.owner_id is None:
        return False
    if user_id is None:
        return True
    return w.owner_id == user_id


def can_delete_template(w: Workflow, user_id: str | None) -> bool:
    return can_edit_template(w, user_id)


def _sanitize_url(raw_url: str) -> str:
    s = raw_url.strip()
    if not s:
        return s
    try:
        parts = urlsplit(s)
    except ValueError:
        return redact_text(s)
    netloc = parts.netloc
    if "@" in netloc:
        _, host_part = netloc.rsplit("@", 1)
        netloc = host_part
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        cleaned_pairs = [
            (k, "" if k.lower() in _SENSITIVE_QUERY_KEYS else redact_text(v))
            for k, v in pairs
        ]
        query = urlencode(cleaned_pairs)
    return redact_text(urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment)))


def sanitize_graph_for_template(
    graph: dict[str, Any],
    *,
    strip_recipient_email: bool = False,
) -> dict[str, Any]:
    """Return a deep-copied graph with credentials, tokens, uploads, and secret headers removed."""
    cleaned = copy.deepcopy(graph or {})
    nodes = cleaned.get("nodes")
    if not isinstance(nodes, list):
        return cleaned

    for node in nodes:
        if not isinstance(node, dict):
            continue
        params = node.get("params")
        if not isinstance(params, dict):
            continue

        node_type = str(node.get("type") or "")
        for key in list(params.keys()):
            low = str(key).lower()
            if low in _SENSITIVE_PARAM_KEYS:
                if low == "credential_id":
                    params[key] = ""
                else:
                    params.pop(key, None)
                continue

            val = params[key]
            if isinstance(val, str):
                if node_type == "source.upload_zip" and low == "upload_id":
                    params[key] = ""
                elif node_type == "notify.webhook" and low == "headers_json" and val.strip():
                    try:
                        hdrs = json.loads(val)
                        if isinstance(hdrs, dict):
                            safe_hdrs = {
                                hk: redact_text(str(hv))
                                for hk, hv in hdrs.items()
                                if str(hk).lower() not in _SENSITIVE_HEADER_KEYS
                            }
                            params[key] = json.dumps(safe_hdrs) if safe_hdrs else ""
                        else:
                            params[key] = ""
                    except (ValueError, TypeError):
                        params[key] = ""
                elif low in {"url", "webhook_url"}:
                    params[key] = _sanitize_url(val)
                elif strip_recipient_email and node_type == "notify.email" and low == "to_email":
                    params[key] = ""
                elif node_type == "notify.telegram" and low == "chat_id" and strip_recipient_email:
                    params[key] = ""
                else:
                    params[key] = redact_text(val)

    return cleaned
