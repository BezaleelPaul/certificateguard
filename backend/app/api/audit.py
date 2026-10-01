from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.database import get_db
from app.models import AuditLog, User
from app.schemas import AuditLogResponse
from app.security.auth import require_teacher

router = APIRouter(prefix="/api/audit-logs", tags=["Audit Logs"])


@router.get("", response_model=List[AuditLogResponse])
async def list_audit_logs(
    current_user: User = Depends(require_teacher),
    db: AsyncSession = Depends(get_db)
):
    """
    Returns immutable audit logs. Never allows modification or deletion.
    Accessible only to teachers and administrators.
    """
    result = await db.execute(
        select(AuditLog).order_by(desc(AuditLog.created_at)).limit(200)
    )
    logs = result.scalars().all()

    response_items = []
    for log in logs:
        # Load actor name if available
        actor_name = None
        if log.actor_user_id:
            user_res = await db.execute(select(User).where(User.id == log.actor_user_id))
            user = user_res.scalar_one_or_none()
            if user:
                actor_name = user.name

        response_items.append(AuditLogResponse(
            id=log.id,
            actor_user_id=log.actor_user_id,
            actor_name=actor_name,
            action=log.action,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            old_value=log.old_value,
            new_value=log.new_value,
            ip_hash=log.ip_hash,
            created_at=log.created_at
        ))

    return response_items
