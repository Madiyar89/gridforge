"""Разрешение центральной учётки узла — см. Credential в models.py.

Порядок поиска: своя учётка узла (node_id) -> учётка группы узла
(group_id) -> учётка вендора узла (vendor) -> учётка по умолчанию (все
три поля NULL) -> ничего (вызывающая сторона тогда требует явную учётку
в запросе, как раньше). Учётка по вендору — по прямому запросу
пользователя (2026-09-21): сетевые группы здесь смешанные (в одной
группе и cisco_ios, и junos), логин реально зависит от вендора
устройства, не от сетевой группы."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Credential, Node, iso
from app.secrets_crypto import decrypt_secret, encrypt_secret


def resolve_credential(db: Session, node: Node) -> dict | None:
    cred = db.query(Credential).filter(Credential.node_id == node.id).first()
    if cred is None and node.group_id is not None:
        cred = db.query(Credential).filter(
            Credential.group_id == node.group_id,
            Credential.node_id.is_(None),
        ).first()
    if cred is None and node.vendor is not None:
        cred = db.query(Credential).filter(
            Credential.vendor == node.vendor,
            Credential.node_id.is_(None),
            Credential.group_id.is_(None),
        ).first()
    if cred is None:
        cred = db.query(Credential).filter(
            Credential.group_id.is_(None),
            Credential.node_id.is_(None),
            Credential.vendor.is_(None),
        ).first()
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
        "node_id": cred.node_id,
        "node_name": cred.node.name if cred.node else None,
        "vendor": cred.vendor.value if cred.vendor else None,
        "label": cred.label,
        "username": cred.username,
        "has_password": bool(cred.password),
        "key_path": cred.key_path,
        "created_at": iso(cred.created_at),
    }
