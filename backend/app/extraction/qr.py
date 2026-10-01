import re
from urllib.parse import urlparse
from typing import Optional, Tuple, Dict, Any
from pydantic import BaseModel
from pypdf import PdfReader
from PIL import Image
import io


class QRDecodeResult(BaseModel):
    raw_url: Optional[str] = None
    hostname: Optional[str] = None
    is_valid_url: bool = False
    error: Optional[str] = None


class QRDomainCheck(BaseModel):
    domain: str
    is_trusted: bool
    matched_issuer_id: Optional[str] = None
    reason: str


class QRExtractor:
    """
    Extracts QR code content from PDF streams or images.
    Implements barcode/QR decoding with pure-python fallback pattern matching.
    """

    def extract_from_file(self, file_path: str, mime_type: str) -> QRDecodeResult:
        # First attempt: If it's a PDF, scan for links/annotations or embedded QR streams
        if mime_type == "application/pdf" or file_path.lower().endswith(".pdf"):
            return self._extract_from_pdf(file_path)
        else:
            return self._extract_from_image(file_path)

    def _extract_from_pdf(self, file_path: str) -> QRDecodeResult:
        try:
            reader = PdfReader(file_path, strict=False)
            
            # 1. Check annotations and Uri links
            for page in reader.pages:
                if "/Annots" in page:
                    for annot in page["/Annots"]:
                        obj = annot.get_object()
                        if "/A" in obj and "/URI" in obj["/A"]:
                            uri = str(obj["/A"]["/URI"])
                            if uri.startswith("http://") or uri.startswith("https://"):
                                return self._parse_url(uri)

            # 2. Check for extracted text containing verification links
            full_text = ""
            for page in reader.pages:
                text = page.extract_text() or ""
                full_text += " " + text

            # Find URLs
            url_match = re.search(r"(https?://[^\s<>\"'{}|\\^`]+(?:verify|cert|credential)[^\s<>\"'{}|\\^`]*)", full_text, re.IGNORECASE)
            if not url_match:
                url_match = re.search(r"(https?://[^\s<>\"'{}|\\^`]+)", full_text)

            if url_match:
                return self._parse_url(url_match.group(1).strip())

            # 3. Check embedded images if pyzbar is installed
            try:
                from pyzbar.pyzbar import decode as pyzbar_decode
                for page in reader.pages:
                    for img in page.images:
                        pil_img = Image.open(io.BytesIO(img.data))
                        barcodes = pyzbar_decode(pil_img)
                        for b in barcodes:
                            decoded_str = b.data.decode("utf-8")
                            return self._parse_url(decoded_str)
            except Exception:
                pass

            return QRDecodeResult(error="No QR code or verification link detected in document")
        except Exception as e:
            return QRDecodeResult(error=f"PDF QR extraction error: {str(e)}")

    def _extract_from_image(self, file_path: str) -> QRDecodeResult:
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            img = Image.open(file_path)
            barcodes = pyzbar_decode(img)
            for b in barcodes:
                decoded_str = b.data.decode("utf-8")
                return self._parse_url(decoded_str)
            return QRDecodeResult(error="No QR code found in image")
        except Exception as e:
            return QRDecodeResult(error=f"Image QR decoding unavailable: {str(e)}")

    def _parse_url(self, raw_url: str) -> QRDecodeResult:
        raw_url = raw_url.strip()
        try:
            parsed = urlparse(raw_url)
            if parsed.scheme in ["http", "https"] and parsed.netloc:
                # Remove port from hostname if present
                hostname = parsed.hostname.lower() if parsed.hostname else ""
                return QRDecodeResult(
                    raw_url=raw_url,
                    hostname=hostname,
                    is_valid_url=True
                )
            return QRDecodeResult(raw_url=raw_url, is_valid_url=False, error="Invalid URL scheme or format")
        except Exception as e:
            return QRDecodeResult(raw_url=raw_url, is_valid_url=False, error=str(e))

    @staticmethod
    def validate_domain(hostname: str, allowed_domain: str) -> bool:
        """
        Validates domain strictly against allowed issuer domain.
        Prevents prefix/suffix injection like:
        - example.com.fake.io (INVALID)
        - fake-example.com (INVALID)
        - verify.example.com (VALID if domain is example.com)
        - example.com (VALID)
        """
        if not hostname or not allowed_domain:
            return False

        h = hostname.lower().strip()
        d = allowed_domain.lower().strip()

        # Exact match
        if h == d:
            return True

        # Proper subdomain match (e.g. verify.example.com for example.com)
        if h.endswith("." + d):
            return True

        return False


qr_extractor = QRExtractor()
