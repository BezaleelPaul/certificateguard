import hashlib
import os
from typing import Tuple, Optional
from pypdf import PdfReader
from PIL import Image
from app.config import settings

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
ALLOWED_MIME_TYPES = {"application/pdf", "image/png", "image/jpeg", "image/pjpeg"}

MAGIC_BYTES = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "xlsx": b"PK\x03\x04",
}

ALLOWED_WORKBOOK_EXTENSIONS = {".xlsx"}
MAX_IMAGE_WIDTH = 6000
MAX_IMAGE_HEIGHT = 6000


class FileValidationError(Exception):
    def __init__(self, message: str, code: str = "FILE_VALIDATION_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)


def compute_sha256(content: bytes) -> str:
    """Calculates SHA-256 hash immediately."""
    hasher = hashlib.sha256()
    hasher.update(content)
    return hasher.hexdigest()


def compute_file_sha256(file_path: str) -> str:
    """Calculates SHA-256 hash of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_file_upload(
    filename: str, content: bytes, mime_type: Optional[str] = None
) -> Tuple[bool, str, str]:
    """
    Validates uploaded file against security constraints:
    - File size
    - Extension
    - Magic bytes
    - Content structure (PDF pages or image dimensions)
    Returns: (is_valid, detected_type, clean_extension)
    Raises FileValidationError on security or structural violation.
    """
    # 1. File size limit
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise FileValidationError(
            f"File size {len(content) / (1024 * 1024):.2f}MB exceeds limit of {settings.MAX_FILE_SIZE_MB}MB",
            code="FILE_TOO_LARGE",
        )

    if len(content) == 0:
        raise FileValidationError("File is empty", code="EMPTY_FILE")

    # 2. Extension check
    _, ext = os.path.splitext(filename)
    clean_ext = ext.lower()
    if clean_ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError(
            f"Extension '{clean_ext}' not permitted. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            code="INVALID_EXTENSION",
        )

    # 3. Magic bytes validation
    detected_type = None
    if content.startswith(b"%PDF-"):
        detected_type = "pdf"
    elif content.startswith(b"\x89PNG"):
        detected_type = "png"
    elif content.startswith(b"\xff\xd8\xff"):
        detected_type = "jpeg"
    else:
        raise FileValidationError(
            "File header does not match any allowed file signature (PDF, PNG, JPEG)",
            code="INVALID_MAGIC_BYTES",
        )

    # Extension must match magic bytes
    if detected_type == "pdf" and clean_ext != ".pdf":
        raise FileValidationError(
            "File content is PDF but extension is not .pdf", code="EXTENSION_MISMATCH"
        )
    if detected_type == "png" and clean_ext != ".png":
        raise FileValidationError(
            "File content is PNG but extension is not .png", code="EXTENSION_MISMATCH"
        )
    if detected_type == "jpeg" and clean_ext not in [".jpg", ".jpeg"]:
        raise FileValidationError(
            "File content is JPEG but extension is not .jpg/.jpeg",
            code="EXTENSION_MISMATCH",
        )

    # 4. Structural validation
    if detected_type == "pdf":
        validate_pdf_structure(content)
    elif detected_type in ["png", "jpeg"]:
        validate_image_structure(content)

    return True, detected_type, clean_ext


def validate_pdf_structure(content: bytes):
    """Parses PDF safely to enforce page count and catch malformed structures."""
    try:
        from io import BytesIO

        reader = PdfReader(BytesIO(content), strict=False)

        num_pages = len(reader.pages)
        if num_pages == 0:
            raise FileValidationError("PDF contains 0 pages", code="EMPTY_PDF")
        if num_pages > settings.MAX_PDF_PAGES:
            raise FileValidationError(
                f"PDF has {num_pages} pages, exceeding maximum allowed of {settings.MAX_PDF_PAGES}",
                code="PDF_PAGE_LIMIT_EXCEEDED",
            )
        # Verify first page can be read
        _ = reader.pages[0].extract_text()
    except FileValidationError:
        raise
    except Exception as e:
        raise FileValidationError(
            f"Malformed or corrupted PDF document: {str(e)}", code="MALFORMED_PDF"
        )


def validate_image_structure(content: bytes):
    """Validates image dimensions and decodability."""
    try:
        from io import BytesIO

        img = Image.open(BytesIO(content))
        img.verify()  # Verifies file integrity

        # Reopen to check dimensions (verify() closes file)
        img = Image.open(BytesIO(content))
        width, height = img.size
        if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT:
            raise FileValidationError(
                f"Image dimensions {width}x{height} exceed maximum permitted {MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT}",
                code="IMAGE_TOO_LARGE",
            )
    except FileValidationError:
        raise
    except Exception as e:
        raise FileValidationError(
            f"Malformed or corrupted image file: {str(e)}", code="MALFORMED_IMAGE"
        )


def validate_workbook_upload(
    filename: str, content: bytes, mime_type: Optional[str] = None
) -> Tuple[bool, str, str]:
    """
    Validates an uploaded analysis workbook (.xlsx) before any parsing:
    - Size limit (same ceiling as certificate uploads)
    - Non-empty content
    - Extension must be .xlsx (no legacy .xls macro-capable workbooks)
    - Magic bytes must be an Office Open XML ZIP container
    - Basic ZIP integrity so malformed containers never reach the parser
    Returns: (is_valid, 'xlsx', '.xlsx')
    Raises FileValidationError on security or structural violation.
    """
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise FileValidationError(
            f"Workbook size {len(content) / (1024 * 1024):.2f}MB exceeds limit of {settings.MAX_FILE_SIZE_MB}MB",
            code="FILE_TOO_LARGE",
        )

    if len(content) == 0:
        raise FileValidationError("Workbook is empty", code="EMPTY_FILE")

    _, ext = os.path.splitext(filename)
    clean_ext = ext.lower()
    if clean_ext not in ALLOWED_WORKBOOK_EXTENSIONS:
        raise FileValidationError(
            f"Extension '{clean_ext}' not permitted for analysis. Allowed: {', '.join(sorted(ALLOWED_WORKBOOK_EXTENSIONS))}",
            code="INVALID_EXTENSION",
        )

    if not content.startswith(MAGIC_BYTES["xlsx"]):
        raise FileValidationError(
            "File header is not an Office Open XML (.xlsx) workbook container",
            code="INVALID_MAGIC_BYTES",
        )

    # Structural sanity: the container must be a readable ZIP archive.
    import zipfile
    from io import BytesIO

    try:
        with zipfile.ZipFile(BytesIO(content)) as zf:
            bad_member = zf.testzip()
            if bad_member is not None:
                raise FileValidationError(
                    f"Workbook ZIP container is corrupted at member '{bad_member}'",
                    code="MALFORMED_WORKBOOK",
                )
            if "xl/workbook.xml" not in zf.namelist():
                raise FileValidationError(
                    "File is a ZIP archive but not a valid Excel workbook (missing xl/workbook.xml)",
                    code="MALFORMED_WORKBOOK",
                )
    except FileValidationError:
        raise
    except Exception as e:
        raise FileValidationError(
            f"Malformed or corrupted workbook: {str(e)}", code="MALFORMED_WORKBOOK"
        )

    return True, "xlsx", clean_ext
