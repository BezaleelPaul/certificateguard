from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel
from app.models import IssuerVerificationStatus


class AdapterVerificationResult(BaseModel):
    verification_status: IssuerVerificationStatus
    certificate_id_returned: Optional[str] = None
    recipient_returned: Optional[str] = None
    course_returned: Optional[str] = None
    status_returned: Optional[str] = None
    raw_evidence: Optional[str] = None
    error_message: Optional[str] = None
    verification_url: Optional[str] = None


class IssuerVerificationAdapter(ABC):
    @abstractmethod
    async def verify(self, certificate_id: str, verification_url: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> AdapterVerificationResult:
        """Verifies a certificate with the issuer verification authority."""
        pass
