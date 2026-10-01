import os
import re
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from pypdf import PdfReader
from PIL import Image


class OCRPageInfo(BaseModel):
    page_number: int
    text: str
    confidence: float
    char_count: int


class OCRResult(BaseModel):
    full_text: str
    confidence: float
    pages: List[OCRPageInfo]
    metadata: Dict[str, Any] = {}
    bounding_boxes: List[Dict[str, Any]] = []


class OCRProvider(ABC):
    @abstractmethod
    async def extract_text(self, file_path: str, mime_type: str) -> OCRResult:
        """Extracts text and structural metadata from PDF or image."""
        pass


class LocalOCRProvider(OCRProvider):
    """
    Default local OCR provider for CertificateGuard.
    Extracts text from PDF native streams, metadata, and handles image files cleanly.
    """

    async def extract_text(self, file_path: str, mime_type: str) -> OCRResult:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found for OCR")

        if mime_type == "application/pdf" or file_path.lower().endswith(".pdf"):
            return self._extract_pdf(file_path)
        else:
            return self._extract_image(file_path)

    def _extract_pdf(self, file_path: str) -> OCRResult:
        pages_info: List[OCRPageInfo] = []
        full_text_parts = []
        pdf_metadata = {}

        try:
            reader = PdfReader(file_path, strict=False)
            if reader.metadata:
                for k, v in reader.metadata.items():
                    key = str(k).replace("/", "")
                    pdf_metadata[key] = str(v)

            for idx, page in enumerate(reader.pages):
                page_text = page.extract_text() or ""
                # Strip excessive whitespace but preserve line structure
                cleaned_page_text = "\n".join([line.strip() for line in page_text.splitlines() if line.strip()])
                char_count = len(cleaned_page_text)
                
                # Confidence heuristic: meaningful character density
                conf = 0.95 if char_count > 30 else (0.5 if char_count > 0 else 0.0)
                
                pages_info.append(OCRPageInfo(
                    page_number=idx + 1,
                    text=cleaned_page_text,
                    confidence=conf,
                    char_count=char_count
                ))
                if cleaned_page_text:
                    full_text_parts.append(cleaned_page_text)

            full_text = "\n\n".join(full_text_parts)
            avg_conf = sum(p.confidence for p in pages_info) / max(len(pages_info), 1)

            return OCRResult(
                full_text=full_text,
                confidence=avg_conf,
                pages=pages_info,
                metadata=pdf_metadata
            )
        except Exception as e:
            # Fallback gracefully
            return OCRResult(
                full_text="",
                confidence=0.0,
                pages=[],
                metadata={"error": str(e)}
            )

    def _extract_image(self, file_path: str) -> OCRResult:
        """Fallback for images when external OCR binary is optional."""
        try:
            img = Image.open(file_path)
            meta = {
                "format": img.format,
                "width": img.width,
                "height": img.height,
                "mode": img.mode
            }
            # If tesseract is installed in the environment, try it
            try:
                import pytesseract
                text = pytesseract.image_to_string(img)
                conf = 0.85 if len(text.strip()) > 20 else 0.4
                return OCRResult(
                    full_text=text.strip(),
                    confidence=conf,
                    pages=[OCRPageInfo(page_number=1, text=text.strip(), confidence=conf, char_count=len(text))],
                    metadata=meta
                )
            except Exception:
                # Return image metadata with placeholder text
                return OCRResult(
                    full_text="[Image Certificate Document]",
                    confidence=0.6,
                    pages=[OCRPageInfo(page_number=1, text="[Image Document]", confidence=0.6, char_count=16)],
                    metadata=meta
                )
        except Exception as e:
            return OCRResult(
                full_text="",
                confidence=0.0,
                pages=[],
                metadata={"error": str(e)}
            )


local_ocr_provider = LocalOCRProvider()
