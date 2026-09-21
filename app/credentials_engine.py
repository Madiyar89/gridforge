"""Разрешение центральной учётки узла — см. Credential в models.py.

Порядок поиска: своя учётка группы узла -> глобальная учётка по
умолчанию (group_id IS NULL) -> ничего (вызывающая сторона тогда
требует явную учётку в запросе, как раньше)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Credential, Node
from app.secrets_crypto import decrypt_secret, encrypt_secret


def resolve_credential(db: Session, node: Node) -> dict | None:
    cred = None
    if node.group_id is not None:
        cred = db.query(Credential).filter(Credential.group_id == node.group_id).first()
    if cred is None:
        cred = db.query(Credential).filter(Credential.group_id.is_(None)).first()
    if cred is None:
        return None
    return {
        "username": cred.username,
        "password": decrypt_secret(cred.password) if cred.password else None,
        "key_path": cred.key_path,
    }


def encrypt_password(password: str | None) -> str | None:
    return encrypt_secret(password) if password else None


def mask_credential(cred: Credential) -> dict:
    return {
        "id": cred.id,
        "group_id": cred.group_id,
        "group_name": cred.group.name if cred.group else None,
        "label": cred.label,
        "username": cred.username,
        "has_password": bool(cred.password),
        "key_path": cred.key_path,
        "created_at": cred.created_at.isoformat(),
    }
