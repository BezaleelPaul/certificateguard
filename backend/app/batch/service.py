"""
Batch analysis orchestration: workbook -> row verdicts -> annotated workbook.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.batch.analyzer import analyze_rows
from app.batch.template import (
    VERDICT_ANOMALY,
    VERDICT_FAKE,
    VERDICT_LEGIT,
    WorkbookFormatError,
    parse_workbook,
    write_results,
)
from app.models import AuditLog, BatchAnalysis, BatchStatus, User
from app.storage import storage_provider

logger = logging.getLogger(__name__)


class BatchAnalysisService:
    """Runs the full analysis lifecycle for one uploaded workbook."""

    async def process_batch(self, batch_id: str, db: AsyncSession) -> BatchAnalysis:
        batch = await self._load_batch(batch_id, db)
        if batch is None:
            raise ValueError(f"Batch {batch_id} not found")

        batch.status = BatchStatus.PROCESSING.value
        batch.processing_started_at = datetime.now(timezone.utc)
        batch.error_message = None
        await db.commit()

        try:
            content = await storage_provider.get_file_bytes(batch.storage_key)
            rows = parse_workbook(content)

            batch.total_rows = len(rows)
            await db.commit()

            uploader_name = await self._load_uploader_name(batch, db)
            results = await analyze_rows(
                rows,
                db,
                batch_id=batch.id,
                uploader_student_id=batch.student_id,
                uploader_name=uploader_name,
                workbook_sha256=batch.sha256,
            )

            annotated = write_results(content, results)
            result_key = await storage_provider.save_analysis_result(
                batch.id, annotated
            )

            counts: Dict[str, int] = {
                VERDICT_LEGIT: 0,
                VERDICT_FAKE: 0,
                VERDICT_ANOMALY: 0,
            }
            for verdict in results:
                counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1

            batch.result_storage_key = result_key
            batch.processed_rows = len(results)
            batch.verdict_counts = json.dumps(counts)
            batch.status = BatchStatus.COMPLETED.value
            batch.processing_completed_at = datetime.now(timezone.utc)

            db.add(
                AuditLog(
                    actor_user_id=batch.user_id,
                    action="BATCH_ANALYSIS_COMPLETED",
                    entity_type="BatchAnalysis",
                    entity_id=batch.id,
                    new_value=(
                        f"rows={len(results)} "
                        f"legit={counts[VERDICT_LEGIT]} "
                        f"fake={counts[VERDICT_FAKE]} "
                        f"anomaly={counts[VERDICT_ANOMALY]}"
                    ),
                )
            )
            await db.commit()
            await db.refresh(batch)
            logger.info("Batch analysis %s completed: %s rows", batch.id, len(results))
            return batch

        except WorkbookFormatError as exc:
            await self._fail(batch, db, "; ".join(exc.errors))
            raise
        except Exception as exc:
            logger.exception("Batch analysis %s failed", batch_id)
            await self._fail(batch, db, f"Analysis failed: {exc}")
            raise

    async def _load_batch(
        self, batch_id: str, db: AsyncSession
    ) -> BatchAnalysis | None:
        result = await db.execute(
            select(BatchAnalysis).where(BatchAnalysis.id == batch_id)
        )
        return result.scalar_one_or_none()

    async def _load_uploader_name(self, batch: BatchAnalysis, db: AsyncSession) -> str:
        result = await db.execute(select(User.name).where(User.id == batch.user_id))
        name = result.scalar_one_or_none()
        return name or "Unknown"

    async def _fail(self, batch: BatchAnalysis, db: AsyncSession, message: str) -> None:
        batch.status = BatchStatus.FAILED.value
        batch.error_message = message[:2000]
        batch.processing_completed_at = datetime.now(timezone.utc)
        db.add(
            AuditLog(
                actor_user_id=batch.user_id,
                action="BATCH_ANALYSIS_FAILED",
                entity_type="BatchAnalysis",
                entity_id=batch.id,
                new_value=message[:500],
            )
        )
        await db.commit()


batch_analysis_service = BatchAnalysisService()
