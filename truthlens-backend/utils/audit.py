"""
utils/audit.py — Audit log utility for TruthLens AI
"""
import logging
from typing import Optional

logger = logging.getLogger("apps.audit")


def log_audit(
    action: str,
    target: str = "",
    ip: str = "",
    actor=None,
    extra_data: dict = None,
):
    """
    Write an entry to the AuditLog model.
    Safe to call even if the database is unavailable (logs to console).
    """
    try:
        from apps.community.models import AuditLog
        AuditLog.objects.create(
            actor_id=str(actor.id) if actor else "",
            actor_email=actor.email if actor else "",
            action=action,
            target=target,
            ip_address=ip or None,
            extra_data=extra_data or {},
        )
    except Exception as exc:
        logger.warning("Could not write audit log: %s — action=%s target=%s", exc, action, target)
