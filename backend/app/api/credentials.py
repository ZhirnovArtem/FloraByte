"""Credentials API — values encrypted at rest, never returned in plaintext."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.core.auth import check_owner, get_current_user
from app.core.crypto import encrypt, decrypt
from app.core.db import get_session
from app.core.masking import mask_secret
from app.core.models import Credential, User

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


class CredentialCreate(BaseModel):
    name: str
    kind: str = Field("generic", description="telegram | llm | webhook | smtp | generic")
    value: str = Field(..., description="Secret value (encrypted at rest)")


def _public(c: Credential) -> dict:
    # never return full value
    try:
        plain = decrypt(c.encrypted_value)
        masked = mask_secret(plain, keep_last=4)
    except Exception:
        masked = "****"
    return {
        "id": c.id,
        "name": c.name,
        "kind": c.kind,
        "value_preview": masked,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


@router.get("")
def list_credentials(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    items = session.exec(select(Credential)).all()
    if user is not None:
        items = [c for c in items if c.owner_id == user.id]
    return {"credentials": [_public(c) for c in items]}


@router.post("")
def create_credential(
    body: CredentialCreate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    c = Credential(
        name=body.name,
        kind=body.kind,
        encrypted_value=encrypt(body.value),
        owner_id=user.id if user else None,
    )
    session.add(c)
    session.commit()
    session.refresh(c)
    return _public(c)


@router.delete("/{credential_id}")
def delete_credential(
    credential_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    c = session.get(Credential, credential_id)
    if not c:
        raise HTTPException(404, "Not found")
    check_owner(c.owner_id, user)
    session.delete(c)
    session.commit()
    return {"ok": True}
