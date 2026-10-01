import re
from typing import Optional, Dict, Any
from pydantic import BaseModel


class ExtractedData(BaseModel):
    recipient_name: Optional[str] = None
    issuer_name: Optional[str] = None
    certificate_id: Optional[str] = None
    course_name: Optional[str] = None
    issue_date: Optional[str] = None
    expiry_date: Optional[str] = None
    qr_url: Optional[str] = None
    raw_ocr_text: str = ""
    extraction_confidence: float = 0.0


class CertificateDataExtractor:
    """
    Deterministic rule-based extractor for academic and training certificates.
    Uses regex patterns, structural anchoring, and contextual proximity.
    """

    # Common Certificate ID patterns
    CERT_ID_PATTERNS = [
        r"\b(CERT-[A-Za-z0-9\-_]+)\b",
        r"(?:Certificate\s+(?:ID|Id|no|number|#|code)\s*[:#\-]?\s*)([A-Za-z0-9\-_]{3,32})",
        r"(?:Credential\s+(?:ID|Id|no|number|#)\s*[:#\-]?\s*)([A-Za-z0-9\-_]{3,32})",
        r"(?:Verification\s*Code\s*[:#\-]?\s*)([A-Za-z0-9\-_]{3,32})",
        r"\b([A-Z0-9]{4,8}-[A-Z0-9]{4,8}-[A-Z0-9]{4,8})\b",
    ]

    # Recipient name patterns
    RECIPIENT_PATTERNS = [
        r"(?:This\s+is\s+to\s+certify\s+that|Certifies\s+that|Awarded\s+to|Presented\s+to)[:\s]+([A-Z][a-zA-Z\.\-']+(?:\s+[A-Z][a-zA-Z\.\-']+){1,3})",
        r"(?:Recipient|Student|Learner)[:\s]+([A-Z][a-zA-Z\s\.\-]{2,40})",
        r"(?:Name)[:\s]+([A-Z][a-zA-Z\s\.\-]{2,40})",
        r"(?:This\s+is\s+to\s+certify\s+that|Certifies\s+that|Awarded\s+to|Presented\s+to)\s*\n*([A-Z][a-zA-Z\s\.\-]{2,40})(?:\s*\n*(?:has|for|successfully|in))",
    ]

    # Course name patterns
    COURSE_PATTERNS = [
        r"(?:successfully\s+completed\s+(?:the\s+course\s+|the\s+program\s+|the\s+requirements\s+for\s+|the\s+))[\"']?([A-Za-z0-9\s,\-\(\)]{4,80})[\"']?(?:\s*\n*(?:on|with|at|course|specialization))?",
        r"(?:Course|Program|Specialization|Track)[:\s]+[\"']?([A-Za-z0-9\s,\-\(\)]{4,80})[\"']?",
        r"(?:Certificate\s+of\s+(?:Completion|Achievement|Excellence)\s+in)\s+([A-Za-z0-9\s,\-\(\)]{4,80})",
    ]

    # Issuer name patterns
    ISSUER_PATTERNS = [
        r"(?:Issued\s+by|Provided\s+by|Authorized\s+by|Institution|University|Platform)[:\s]+([A-Za-z0-9\s,\.\-]{3,60})",
        r"\b([A-Za-z0-9\s]+(?:University|Institute|Academy|College|School|Coursera|edX|Udacity))\b",
    ]

    # Date patterns
    DATE_PATTERNS = [
        r"(?:Issue(?:d)?\s*Date|Date\s*of\s*Issue|Date)[:\s]+(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})",
    ]

    EXPIRY_PATTERNS = [
        r"(?:Expiry\s*Date|Expiration\s*Date|Valid\s*Through|Expires)[:\s]+(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})",
    ]

    URL_PATTERNS = [
        r"(https?://[^\s<>\"'{}|\\^`]+)",
    ]

    def extract(self, raw_text: str, qr_url: Optional[str] = None) -> ExtractedData:
        data = ExtractedData(raw_ocr_text=raw_text)
        confidence_points = 0
        total_possible = 6

        # 1. Extract Certificate ID
        for pattern in self.CERT_ID_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                data.certificate_id = match.group(1).strip()
                confidence_points += 1
                break

        # If not found in text, check if query param or path in QR URL contains an ID
        if not data.certificate_id and qr_url:
            m = re.search(r"[?&](?:id|cert_id|code|credential)=([A-Za-z0-9\-_]+)", qr_url, re.IGNORECASE)
            if m:
                data.certificate_id = m.group(1).strip()
                confidence_points += 0.8
            else:
                m2 = re.search(r"/(?:verify|certificates|cert)/([A-Za-z0-9\-_]+)", qr_url, re.IGNORECASE)
                if m2:
                    data.certificate_id = m2.group(1).strip()
                    confidence_points += 0.8

        # 2. Extract Recipient Name
        for pattern in self.RECIPIENT_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                name_candidate = match.group(1).strip()
                # Clean up newlines and trailing words like "has", "for"
                name_candidate = name_candidate.splitlines()[0].strip()
                name_candidate = re.sub(r"\s+(?:has|for|is|to|in|of|on)\b.*$", "", name_candidate, flags=re.IGNORECASE).strip()
                if len(name_candidate) >= 3 and not any(kw in name_candidate.lower() for kw in ["completion", "excellence", "achievement", "participat"]):
                    data.recipient_name = name_candidate
                    confidence_points += 1
                    break

        # 3. Extract Course / Title
        for pattern in self.COURSE_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                course_candidate = match.group(1).strip()
                course_candidate = course_candidate.splitlines()[0].strip()
                course_candidate = re.sub(r"\s+(?:on|with|at|dated?|issue(?:\s*date)?)\b.*$", "", course_candidate, flags=re.IGNORECASE).strip()
                data.course_name = course_candidate
                confidence_points += 1
                break
                break

        # 4. Extract Issuer Name
        for pattern in self.ISSUER_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                data.issuer_name = match.group(1).strip()
                confidence_points += 1
                break

        # 5. Extract Issue Date
        for pattern in self.DATE_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                data.issue_date = match.group(1).strip()
                confidence_points += 0.5
                break

        # 6. Extract Expiry Date
        for pattern in self.EXPIRY_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                data.expiry_date = match.group(1).strip()
                confidence_points += 0.5
                break

        # 7. QR URL
        if qr_url:
            data.qr_url = qr_url
            confidence_points += 1
        else:
            for pattern in self.URL_PATTERNS:
                match = re.search(pattern, raw_text, re.IGNORECASE)
                if match:
                    data.qr_url = match.group(1).strip()
                    confidence_points += 0.5
                    break

        data.extraction_confidence = round(min(confidence_points / total_possible, 1.0), 2)
        return data


certificate_extractor = CertificateDataExtractor()
