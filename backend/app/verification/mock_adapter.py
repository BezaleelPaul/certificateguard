import json
import httpx
from typing import Optional, Dict, Any
from app.verification.adapter import IssuerVerificationAdapter, AdapterVerificationResult
from app.models import IssuerVerificationStatus
from app.config import settings

# In-memory mock directory matching requirements in Section 15
MOCK_RECORDS = {
    "CERT-1001": {
        "certificate_id": "CERT-1001",
        "recipient_name": "Rahul Kumar",
        "course_name": "Web Security Specialization",
        "issuer": "Example University",
        "status": "VALID"
    },
    "CERT-1002": {
        "certificate_id": "CERT-1002",
        "recipient_name": "Bezaleel Paul",
        "course_name": "Machine Learning Certificate",
        "issuer": "Example University",
        "status": "VALID"
    },
    "CERT-1003": {
        "certificate_id": "CERT-1003",
        "status": "INVALID",
        "error_message": "Certificate ID revoked or does not exist"
    },
    "CERT-1004": {
        "certificate_id": "CERT-1004",
        "recipient_name": "Sarah Chen",
        "course_name": "Cloud Architecture",
        "issuer": "Example University",
        "status": "VALID"
    }
}


class MockIssuerAdapter(IssuerVerificationAdapter):
    """
    Mock adapter for automated testing and local verification.
    Can either query the running mock HTTP server or use authoritative fallback table.
    """

    def __init__(self, mock_server_url: Optional[str] = None):
        self.mock_server_url = mock_server_url or settings.MOCK_ISSUER_URL

    async def verify(self, certificate_id: str, verification_url: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> AdapterVerificationResult:
        if not certificate_id:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.ERROR,
                error_message="Certificate ID is required for verification"
            )

        cert_id = certificate_id.strip()

        # Try HTTP request to mock issuer server if available
        try:
            target_url = f"{self.mock_server_url.rstrip('/')}/mock-issuer/verify"
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(target_url, params={"cert_id": cert_id})
                if resp.status_code == 200:
                    data = resp.json()
                    status_str = data.get("status", "INVALID")
                    v_status = IssuerVerificationStatus.VALID if status_str == "VALID" else IssuerVerificationStatus.INVALID
                    return AdapterVerificationResult(
                        verification_status=v_status,
                        certificate_id_returned=data.get("certificate_id"),
                        recipient_returned=data.get("recipient_name"),
                        course_returned=data.get("course_name"),
                        status_returned=status_str,
                        raw_evidence=json.dumps(data),
                        verification_url=target_url,
                        error_message=data.get("error_message")
                    )
        except Exception:
            pass  # Fall back to internal mock table

        # Fallback to internal authoritative mock records
        record = MOCK_RECORDS.get(cert_id)
        if not record or record.get("status") == "INVALID":
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.INVALID,
                certificate_id_returned=cert_id,
                status_returned="INVALID",
                raw_evidence=json.dumps({"certificate_id": cert_id, "status": "INVALID"}),
                error_message="Certificate ID does not exist in official registry or is revoked"
            )

        return AdapterVerificationResult(
            verification_status=IssuerVerificationStatus.VALID,
            certificate_id_returned=record["certificate_id"],
            recipient_returned=record.get("recipient_name"),
            course_returned=record.get("course_name"),
            status_returned=record.get("status"),
            raw_evidence=json.dumps(record),
            verification_url=verification_url or f"https://example.edu/verify?id={cert_id}"
        )


mock_issuer_adapter = MockIssuerAdapter()
