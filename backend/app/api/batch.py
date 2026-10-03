import json
from typing import List

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import Response
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import database as app_db
from app.batch.service import batch_analysis_service
from app.batch.template import (
    WorkbookFormatError,
    build_template_bytes,
    expected_format_description,
    parse_workbook,
)
from app.database import get_db
from app.models import BatchAnalysis, BatchStatus, User, UserRole
from app.schemas import BatchAnalysisResponse
from app.security.auth import get_current_user
from app.security.validation import (
    FileValidationError,
    compute_sha256,
    validate_workbook_upload,
)
from app.storage import storage_provider

router = APIRouter(prefix="/api/batch", tags=["Batch Analysis"])

WORKBOOK_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)


async def run_batch_background(batch_id: str):
    async with app_db.AsyncSessionLocal() as session:
        try:
            await batch_analysis_service.process_batch(batch_id, session)
        except Exception as e:
            print(f"Background batch processing failed for {batch_id}: {e}")


def _to_response(batch: BatchAnalysis) -> BatchAnalysisResponse:
    verdict_counts = None
    if batch.verdict_counts:
        try:
            verdict_counts = json.loads(batch.verdict_counts)
        except json.JSONDecodeError:
            verdict_counts = None
    return BatchAnalysisResponse(
        id=batch.id,
        user_id=batch.user_id,
        original_filename=batch.original_filename,
        file_size=batch.file_size,
        sha256=batch.sha256,
        status=batch.status,
        total_rows=batch.total_rows,
        processed_rows=batch.processed_rows,
        verdict_counts=verdict_counts,
        error_message=batch.error_message,
        result_ready=bool(batch.result_storage_key)
        and batch.status == BatchStatus.COMPLETED.value,
        created_at=batch.created_at,
        processing_started_at=batch.processing_started_at,
        processing_completed_at=batch.processing_completed_at,
    )


def _assert_accessible(batch: BatchAnalysis, current_user: User):
    if current_user.role == UserRole.STUDENT.value and batch.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you cannot access another user's batch analysis",
        )


@router.get("/template")
async def download_template(current_user: User = Depends(get_current_user)):
    """
    Official workbook template. The output/analysis columns are pre-locked;
    only the input zone is meant to be edited.
    """
    content = build_template_bytes()
    return Response(
        content=content,
        media_type=WORKBOOK_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="certificateguard_batch_template.xlsx"'
        },
    )


@router.post("", response_model=BatchAnalysisResponse)
async def upload_batch(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Uploads a batch workbook that strictly follows the format contract:
    worksheet 'Certificates', exact header row, empty output/analysis zone.
    Queues row-level analysis and returns the batch record.
    """
    content = await file.read()

    # 1. Security validation (size, extension, ZIP magic bytes, container integrity)
    try:
        validate_workbook_upload(file.filename or "", content, file.content_type)
    except FileValidationError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security/format rejection: {ve.message} [{ve.code}]",
        )

    # 2. Strict format-contract validation before anything is persisted
    try:
        rows = parse_workbook(content)
    except WorkbookFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Workbook does not follow the required format",
                "expected": expected_format_description(),
                "errors": exc.errors,
            },
        )

    sha256_hash = compute_sha256(content)
    storage_key, stored_filename, _ = await storage_provider.save_submission(
        content, ".xlsx"
    )

    batch = BatchAnalysis(
        user_id=current_user.id,
        student_id=current_user.student_id,
        original_filename=file.filename,
        stored_filename=stored_filename,
        storage_key=storage_key,
        mime_type=WORKBOOK_MEDIA_TYPE,
        file_size=len(content),
        sha256=sha256_hash,
        status=BatchStatus.PROCESSING.value,
        total_rows=len(rows),
    )
    db.add(batch)
    await db.commit()
    await db.refresh(batch)

    background_tasks.add_task(run_batch_background, batch.id)
    return _to_response(batch)


@router.get("", response_model=List[BatchAnalysisResponse])
async def list_batches(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(BatchAnalysis).order_by(desc(BatchAnalysis.created_at))
    if current_user.role == UserRole.STUDENT.value:
        query = query.where(BatchAnalysis.user_id == current_user.id)
    result = await db.execute(query)
    return [_to_response(b) for b in result.scalars().all()]


@router.get("/{batch_id}", response_model=BatchAnalysisResponse)
async def get_batch(
    batch_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(BatchAnalysis).where(BatchAnalysis.id == batch_id))
    batch = result.scalar_one_or_none()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch analysis not found")
    _assert_accessible(batch, current_user)
    return _to_response(batch)


@router.post("/{batch_id}/process", response_model=BatchAnalysisResponse)
async def trigger_process(
    batch_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Synchronously runs (or re-runs) the analysis for a batch."""
    result = await db.execute(select(BatchAnalysis).where(BatchAnalysis.id == batch_id))
    batch = result.scalar_one_or_none()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch analysis not found")
    _assert_accessible(batch, current_user)

    try:
        batch = await batch_analysis_service.process_batch(batch_id, db)
    except WorkbookFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Stored workbook no longer matches the format contract",
                "errors": exc.errors,
            },
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Batch analysis failed",
        )
    return _to_response(batch)


@router.get("/{batch_id}/result")
async def download_result(
    batch_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Downloads the annotated workbook with the system-written analysis zone."""
    result = await db.execute(select(BatchAnalysis).where(BatchAnalysis.id == batch_id))
    batch = result.scalar_one_or_none()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch analysis not found")
    _assert_accessible(batch, current_user)

    if not batch.result_storage_key or batch.status != BatchStatus.COMPLETED.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Result workbook is not ready yet",
        )

    try:
        content = await storage_provider.get_file_bytes(batch.result_storage_key)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, detail="Result workbook not found in storage"
        )

    filename = f"analysed_{batch.original_filename or 'workbook.xlsx'}"
    return Response(
        content=content,
        media_type=WORKBOOK_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
