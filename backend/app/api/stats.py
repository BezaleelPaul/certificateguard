from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models import Submission, Issuer, Student, UserRole, User
from app.schemas import PlatformStatsResponse
from app.security.auth import get_current_user

router = APIRouter(prefix="/api/stats", tags=["Statistics"])


@router.get("", response_model=PlatformStatsResponse)
async def get_platform_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    sub_query = select(Submission)
    # If student, limit counts to own submissions
    if current_user.role == UserRole.STUDENT.value:
        sub_query = sub_query.where(Submission.student_id == current_user.student_id)

    subs = (await db.execute(sub_query)).scalars().all()

    total_submissions = len(subs)
    processing = sum(1 for s in subs if s.status == "PROCESSING")
    verified = sum(1 for s in subs if s.status == "VERIFIED")
    needs_review = sum(1 for s in subs if s.status == "REVIEW")
    failed = sum(1 for s in subs if s.status == "FAILED")
    unverifiable = sum(1 for s in subs if s.status == "UNVERIFIABLE")

    total_issuers = (await db.execute(select(func.count(Issuer.id)))).scalar() or 0
    active_students = (await db.execute(select(func.count(Student.id)))).scalar() or 0

    return PlatformStatsResponse(
        total_submissions=total_submissions,
        processing=processing,
        verified=verified,
        needs_review=needs_review,
        failed=failed,
        unverifiable=unverifiable,
        total_issuers=total_issuers,
        active_students=active_students
    )
