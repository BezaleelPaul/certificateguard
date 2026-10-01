import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, status
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc
from sqlalchemy.orm import selectinload
from app.database import get_db, AsyncSessionLocal
from app.models import (
    Submission, Student, User, UserRole, TeacherReview, AuditLog,
    ExtractedCertificateData, IssuerVerification, Anomaly,
    DuplicateMatch, VerificationResult, SubmissionStatus, TeacherReviewDecision
)
from app.schemas import (
    SubmissionCreateResponse, SubmissionDetailResponse, AnomalyResponse,
    TeacherReviewCreate, TeacherReviewResponse
)
from app.security.auth import get_current_user, require_teacher
from app.security.validation import validate_file_upload, compute_sha256, FileValidationError
from app.storage import storage_provider
from app.services.pipeline import verification_pipeline

router = APIRouter(prefix="/api/submissions", tags=["Submissions"])


async def run_pipeline_background(submission_id: str):
    async with AsyncSessionLocal() as session:
        try:
            await verification_pipeline.process_submission(submission_id, session)
        except Exception as e:
            print(f"Background pipeline processing failed for {submission_id}: {e}")


@router.post("", response_model=SubmissionCreateResponse)
async def upload_certificate(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload an untrusted certificate file (PDF, PNG, JPG).
    Enforces MIME, magic byte, dimension/page limits, SHA-256 calculation,
    and isolates file storage before queuing verification.
    """
    # 1. Ensure submitting user has an associated student profile
    if current_user.role == UserRole.STUDENT.value and not current_user.student_id:
        # Auto-link or find student profile
        stud_res = await db.execute(select(Student).where(Student.user_id == current_user.id))
        student = stud_res.scalar_one_or_none()
        if not student:
            # Create student record for user
            student = Student(
                user_id=current_user.id,
                student_identifier=f"STU-{current_user.id[:6].upper()}",
                full_name=current_user.name,
                email=current_user.email
            )
            db.add(student)
            await db.flush()
            current_user.student_id = student.id
            await db.flush()
    else:
        student = None
        if current_user.student_id:
            stud_res = await db.execute(select(Student).where(Student.id == current_user.student_id))
            student = stud_res.scalar_one_or_none()
        if not student:
            # Fallback to any active student or create one
            stud_res = await db.execute(select(Student))
            student = stud_res.scalars().first()

    student_id = student.id if student else current_user.id

    # 2. Read untrusted file content
    content = await file.read()

    # 3. File Security Validation (Magic bytes, extension, limits)
    try:
        _, detected_type, clean_ext = validate_file_upload(file.filename, content, file.content_type)
    except FileValidationError as ve:
        # Quarantine malformed content for audit and fail cleanly
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security/format rejection: {ve.message} [{ve.code}]"
        )

    # 4. Compute SHA-256 hash immediately
    sha256_hash = compute_sha256(content)

    # 5. Save securely in storage abstraction with generated internal UUID
    storage_key, stored_filename, full_path = await storage_provider.save_submission(content, clean_ext)

    # 6. Create Submission record (status is ALWAYS PROCESSING initially)
    submission = Submission(
        student_id=student_id,
        original_filename=file.filename,
        stored_filename=stored_filename,
        storage_key=storage_key,
        mime_type=file.content_type or f"application/{detected_type}",
        file_size=len(content),
        sha256=sha256_hash,
        status=SubmissionStatus.PROCESSING.value
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    # 7. Record Audit Log
    audit = AuditLog(
        actor_user_id=current_user.id,
        action="CERTIFICATE_UPLOADED",
        entity_type="Submission",
        entity_id=submission.id,
        new_value=f"Uploaded {file.filename} (SHA256: {sha256_hash[:16]}...)"
    )
    db.add(audit)
    await db.commit()

    # 8. Queue Asynchronous Worker
    background_tasks.add_task(run_pipeline_background, submission.id)

    return SubmissionCreateResponse(
        id=submission.id,
        student_id=submission.student_id,
        original_filename=submission.original_filename,
        file_size=submission.file_size,
        sha256=submission.sha256,
        status=submission.status,
        uploaded_at=submission.uploaded_at
    )


@router.get("", response_model=List[SubmissionDetailResponse])
async def list_submissions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Submission).options(
        selectinload(Submission.student),
        selectinload(Submission.extracted_data),
        selectinload(Submission.issuer_verifications),
        selectinload(Submission.anomalies),
        selectinload(Submission.duplicate_matches),
        selectinload(Submission.verification_result),
        selectinload(Submission.reviews).selectinload(TeacherReview.teacher)
    ).order_by(desc(Submission.uploaded_at))

    # Server-side authorization check: students only see their own certificates!
    if current_user.role == UserRole.STUDENT.value:
        query = query.where(Submission.student_id == current_user.student_id)

    result = await db.execute(query)
    submissions = result.scalars().all()
    return submissions


@router.get("/{submission_id}", response_model=SubmissionDetailResponse)
async def get_submission(
    submission_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Submission).options(
        selectinload(Submission.student),
        selectinload(Submission.extracted_data),
        selectinload(Submission.issuer_verifications),
        selectinload(Submission.anomalies),
        selectinload(Submission.duplicate_matches),
        selectinload(Submission.verification_result),
        selectinload(Submission.reviews).selectinload(TeacherReview.teacher)
    ).where(Submission.id == submission_id)

    result = await db.execute(query)
    submission = result.scalar_one_or_none()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Critical Security Check: Ensure student cannot access other students' private submissions
    if current_user.role == UserRole.STUDENT.value and submission.student_id != current_user.student_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You cannot view another student's certificate submission"
        )

    return submission


@router.get("/{submission_id}/file")
async def get_submission_file(
    submission_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Submission).where(Submission.id == submission_id))
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Authorization Check
    if current_user.role == UserRole.STUDENT.value and submission.student_id != current_user.student_id:
        raise HTTPException(status_code=403, detail="Access denied")

    file_path = storage_provider.get_file_path(submission.storage_key)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File object not found on storage")

    return FileResponse(
        path=file_path,
        media_type=submission.mime_type,
        filename=submission.original_filename
    )


@router.post("/{submission_id}/process", response_model=SubmissionDetailResponse)
async def trigger_process(
    submission_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Submission).where(Submission.id == submission_id))
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if current_user.role == UserRole.STUDENT.value and submission.student_id != current_user.student_id:
        raise HTTPException(status_code=403, detail="Access denied")

    await verification_pipeline.process_submission(submission_id, db)
    return await get_submission(submission_id, current_user, db)


@router.get("/{submission_id}/evidence")
async def get_submission_evidence_report(
    submission_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    sub_res = await db.execute(select(Submission).where(Submission.id == submission_id))
    submission = sub_res.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if current_user.role == UserRole.STUDENT.value and submission.student_id != current_user.student_id:
        raise HTTPException(status_code=403, detail="Access denied")

    report_key = f"reports/report_{submission_id}.json"
    try:
        report_bytes = await storage_provider.get_file_bytes(report_key)
        return PlainTextResponse(report_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=404, detail="Evidence report not yet generated")


@router.get("/{submission_id}/anomalies", response_model=List[AnomalyResponse])
async def get_submission_anomalies(
    submission_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    sub_res = await db.execute(select(Submission).where(Submission.id == submission_id))
    submission = sub_res.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if current_user.role == UserRole.STUDENT.value and submission.student_id != current_user.student_id:
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(Anomaly).where(Anomaly.submission_id == submission_id).order_by(Anomaly.created_at)
    )
    return result.scalars().all()


@router.post("/{submission_id}/review", response_model=TeacherReviewResponse)
async def review_submission(
    submission_id: str,
    review_in: TeacherReviewCreate,
    current_user: User = Depends(require_teacher),
    db: AsyncSession = Depends(get_db)
):
    """
    Teacher review action (APPROVE, REJECT, REQUEST_EVIDENCE).
    Mandates reason for REJECT and REQUEST_EVIDENCE.
    Updates submission status, writes audit log, preserves automated evidence.
    """
    if review_in.decision in [TeacherReviewDecision.REJECT, TeacherReviewDecision.REQUEST_EVIDENCE]:
        if not review_in.reason or len(review_in.reason.strip()) < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A detailed reason is required when rejecting or requesting additional evidence."
            )

    sub_res = await db.execute(select(Submission).where(Submission.id == submission_id))
    submission = sub_res.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    old_status = submission.status

    # Map teacher decision to final status without erasing automated evidence
    if review_in.decision == TeacherReviewDecision.APPROVE:
        submission.status = SubmissionStatus.VERIFIED.value
    elif review_in.decision == TeacherReviewDecision.REJECT:
        submission.status = SubmissionStatus.FAILED.value
    elif review_in.decision == TeacherReviewDecision.REQUEST_EVIDENCE:
        submission.status = SubmissionStatus.REVIEW.value

    review = TeacherReview(
        submission_id=submission_id,
        teacher_id=current_user.id,
        decision=review_in.decision.value,
        reason=review_in.reason,
        notes=review_in.notes
    )
    db.add(review)

    # Append-only immutable audit log
    audit = AuditLog(
        actor_user_id=current_user.id,
        action=f"TEACHER_REVIEW_{review_in.decision.value}",
        entity_type="Submission",
        entity_id=submission_id,
        old_value=old_status,
        new_value=submission.status
    )
    db.add(audit)

    await db.commit()
    await db.refresh(review)

    return TeacherReviewResponse(
        id=review.id,
        teacher_id=review.teacher_id,
        teacher_name=current_user.name,
        decision=review.decision,
        reason=review.reason,
        notes=review.notes,
        created_at=review.created_at
    )
