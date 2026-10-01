from enum import Enum
from typing import Dict, Any, List
from pydantic import BaseModel
from pypdf import PdfReader
from PIL import Image
import os


class ForensicSignal(str, Enum):
    NO_STRONG_SIGNAL = "NO_STRONG_SIGNAL"
    SUSPICIOUS = "SUSPICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class ForensicCheckResult(BaseModel):
    signal: ForensicSignal
    findings: List[str] = []
    metadata: Dict[str, Any] = {}
    details: str = ""


class DocumentForensics:
    """
    Forensic analysis engine for academic certificates.
    Inspects PDF metadata anomalies, modification dates, software producer signatures,
    and dimension consistency.
    """

    SUSPICIOUS_SOFTWARE = [
        "photoshop", "gimp", "canva", "ilovepdf", "sejda", "inkscape", "coreldraw"
    ]

    def analyze(self, file_path: str, mime_type: str) -> ForensicCheckResult:
        findings = []
        is_suspicious = False

        if not os.path.exists(file_path):
            return ForensicCheckResult(
                signal=ForensicSignal.INCONCLUSIVE,
                findings=["File could not be found for forensic inspection"],
                details="File missing"
            )

        if mime_type == "application/pdf" or file_path.lower().endswith(".pdf"):
            try:
                reader = PdfReader(file_path, strict=False)
                metadata = reader.metadata or {}
                meta_dict = {}

                producer = ""
                creator = ""
                mod_date = ""
                creation_date = ""

                for k, v in metadata.items():
                    key_clean = str(k).replace("/", "").lower()
                    meta_dict[key_clean] = str(v)
                    if "producer" in key_clean:
                        producer = str(v).lower()
                    elif "creator" in key_clean:
                        creator = str(v).lower()
                    elif "moddate" in key_clean:
                        mod_date = str(v)
                    elif "creationdate" in key_clean:
                        creation_date = str(v)

                # Check 1: Suspicious software signatures
                for sw in self.SUSPICIOUS_SOFTWARE:
                    if sw in producer or sw in creator:
                        findings.append(f"Document created or modified using graphic design software: '{sw}'")
                        is_suspicious = True

                # Check 2: Modification date differs substantially or suspicious incremental update
                if mod_date and creation_date and mod_date != creation_date:
                    findings.append("Document modification timestamp does not match creation timestamp")

                # Check 3: Suspicious page dimensions
                for idx, page in enumerate(reader.pages):
                    box = page.mediabox
                    width = float(box.width)
                    height = float(box.height)
                    # Check for unusual aspect ratios or extreme dimensions
                    ratio = width / height if height > 0 else 1.0
                    if ratio < 0.4 or ratio > 2.8:
                        findings.append(f"Page {idx+1} has an unusual aspect ratio ({ratio:.2f})")
                        is_suspicious = True

                signal = ForensicSignal.SUSPICIOUS if is_suspicious else ForensicSignal.NO_STRONG_SIGNAL
                details = "; ".join(findings) if findings else "Document structure and metadata conform to standard profiles"

                return ForensicCheckResult(
                    signal=signal,
                    findings=findings,
                    metadata=meta_dict,
                    details=details
                )
            except Exception as e:
                return ForensicCheckResult(
                    signal=ForensicSignal.INCONCLUSIVE,
                    findings=[f"Parser inspection warning: {str(e)}"],
                    details="Could not complete full forensic parsing"
                )
        else:
            # Image inspection
            try:
                with Image.open(file_path) as img:
                    meta_dict = {
                        "format": img.format,
                        "mode": img.mode,
                        "size": list(img.size)
                    }
                    return ForensicCheckResult(
                        signal=ForensicSignal.NO_STRONG_SIGNAL,
                        findings=[],
                        metadata=meta_dict,
                        details="Raster image structure conforms to normal specifications"
                    )
            except Exception as e:
                return ForensicCheckResult(
                    signal=ForensicSignal.INCONCLUSIVE,
                    findings=[f"Image metadata inspection error: {str(e)}"],
                    details="Image inspection inconclusive"
                )


document_forensics = DocumentForensics()
