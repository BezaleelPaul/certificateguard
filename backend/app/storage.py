import os
import shutil
import uuid
from abc import ABC, abstractmethod
from typing import Optional, BinaryIO
from pathlib import Path
from app.config import settings


class StorageProvider(ABC):
    @abstractmethod
    async def save_submission(
        self, file_content: bytes, extension: str
    ) -> tuple[str, str, str]:
        """Saves file into storage. Returns (storage_key, stored_filename, full_path)."""
        pass

    @abstractmethod
    async def get_file_bytes(self, storage_key: str) -> bytes:
        """Retrieves raw file bytes."""
        pass

    @abstractmethod
    def get_file_path(self, storage_key: str) -> str:
        """Returns the local file path for file operations."""
        pass

    @abstractmethod
    async def quarantine_file(self, storage_key: str, reason: str) -> str:
        """Moves a malformed or suspicious file to quarantine directory."""
        pass

    @abstractmethod
    async def save_report(self, submission_id: str, report_content: str) -> str:
        """Saves verification report to storage."""
        pass

    @abstractmethod
    async def save_analysis_result(self, batch_id: str, content: bytes) -> str:
        """Saves an annotated batch-analysis workbook. Returns storage key."""
        pass


class LocalStorageProvider(StorageProvider):
    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path or settings.STORAGE_PATH).resolve()
        self.submissions_dir = self.base_path / "submissions"
        self.processed_dir = self.base_path / "processed"
        self.reports_dir = self.base_path / "reports"
        self.quarantine_dir = self.base_path / "quarantine"

        # Ensure all required storage directories exist
        for d in [
            self.submissions_dir,
            self.processed_dir,
            self.reports_dir,
            self.quarantine_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    async def save_submission(
        self, file_content: bytes, extension: str
    ) -> tuple[str, str, str]:
        # Generate internal UUID to never trust original filename
        internal_id = str(uuid.uuid4())
        clean_ext = extension.lower().strip()
        if not clean_ext.startswith("."):
            clean_ext = f".{clean_ext}"

        stored_filename = f"{internal_id}{clean_ext}"
        storage_key = f"submissions/{stored_filename}"
        target_path = self.submissions_dir / stored_filename

        with open(target_path, "wb") as f:
            f.write(file_content)

        return storage_key, stored_filename, str(target_path)

    async def get_file_bytes(self, storage_key: str) -> bytes:
        full_path = self.base_path / storage_key
        if not full_path.exists():
            raise FileNotFoundError(
                f"Storage object '{storage_key}' not found at {full_path}"
            )
        with open(full_path, "rb") as f:
            return f.read()

    def get_file_path(self, storage_key: str) -> str:
        full_path = self.base_path / storage_key
        return str(full_path)

    async def quarantine_file(self, storage_key: str, reason: str) -> str:
        source_path = self.base_path / storage_key
        if not source_path.exists():
            return ""

        filename = source_path.name
        quarantine_filename = f"quarantine_{filename}"
        target_path = self.quarantine_dir / quarantine_filename

        shutil.move(str(source_path), str(target_path))

        # Write quarantine reason metadata
        meta_path = self.quarantine_dir / f"{quarantine_filename}.reason.txt"
        with open(meta_path, "w", encoding="utf-8") as f:
            f.write(f"Reason: {reason}\nOriginal Key: {storage_key}\n")

        new_storage_key = f"quarantine/{quarantine_filename}"
        return new_storage_key

    async def save_report(self, submission_id: str, report_content: str) -> str:
        report_filename = f"report_{submission_id}.json"
        target_path = self.reports_dir / report_filename
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        return f"reports/{report_filename}"

    async def save_analysis_result(self, batch_id: str, content: bytes) -> str:
        result_filename = f"analysis_{batch_id}.xlsx"
        target_path = self.processed_dir / result_filename
        with open(target_path, "wb") as f:
            f.write(content)
        return f"processed/{result_filename}"


# Global storage instance
storage_provider = LocalStorageProvider()
