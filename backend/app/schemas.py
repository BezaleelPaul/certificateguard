from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models import (
    UserRole,
    SubmissionStatus,
    IssuerVerificationType,
    IssuerVerificationStatus,
    AnomalySeverity,
    DuplicateMatchType,
    TeacherReviewDecision,
)


# Authentication Schemas
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SwitchRoleRequest(BaseModel):
    target_role: UserRole


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: UserRole
    student_id: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class StudentResponse(BaseModel):
    id: str
    student_identifier: str
    full_name: str
    email: str
    department: str
    section: str

    model_config = ConfigDict(from_attributes=True)


# Submission Schemas
class SubmissionCreateResponse(BaseModel):
    id: str
    student_id: str
    original_filename: str
    file_size: int
    sha256: str
    status: SubmissionStatus
    uploaded_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ExtractedDataResponse(BaseModel):
    id: str
    recipient_name: Optional[str] = None
    issuer_name: Optional[str] = None
    certificate_id: Optional[str] = None
    course_name: Optional[str] = None
    issue_date: Optional[str] = None
    expiry_date: Optional[str] = None
    qr_url: Optional[str] = None
    raw_ocr_text: Optional[str] = None
    extraction_confidence: float

    model_config = ConfigDict(from_attributes=True)


class IssuerVerificationResponse(BaseModel):
    id: str
    issuer_id: Optional[str] = None
    verification_method: str
    verification_url: Optional[str] = None
    certificate_id_submitted: Optional[str] = None
    certificate_id_returned: Optional[str] = None
    recipient_returned: Optional[str] = None
    course_returned: Optional[str] = None
    status_returned: Optional[str] = None
    raw_evidence: Optional[str] = None
    verification_status: str
    verified_at: Optional[datetime] = None
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AnomalyResponse(BaseModel):
    id: str
    type: str
    severity: AnomalySeverity
    title: str
    description: str
    evidence: Optional[str] = None
    confidence: float
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DuplicateMatchResponse(BaseModel):
    id: str
    matched_submission_id: str
    match_type: DuplicateMatchType
    similarity: float
    evidence: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VerificationResultResponse(BaseModel):
    id: str
    issuer_verification: str
    identity_verification: str
    qr_verification: str
    certificate_id_verification: str
    document_integrity: str
    duplicate_check: str
    anomaly_check: str
    synthetic_media_signal: str
    final_status: SubmissionStatus
    confidence: float
    reason_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TeacherReviewResponse(BaseModel):
    id: str
    teacher_id: str
    teacher_name: Optional[str] = None
    decision: TeacherReviewDecision
    reason: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TeacherReviewCreate(BaseModel):
    decision: TeacherReviewDecision
    reason: Optional[str] = None
    notes: Optional[str] = None


class SubmissionDetailResponse(BaseModel):
    id: str
    student_id: str
    student: Optional[StudentResponse] = None
    original_filename: str
    stored_filename: str
    mime_type: str
    file_size: int
    sha256: str
    uploaded_at: datetime
    status: SubmissionStatus
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
    extracted_data: Optional[ExtractedDataResponse] = None
    issuer_verifications: List[IssuerVerificationResponse] = []
    anomalies: List[AnomalyResponse] = []
    duplicate_matches: List[DuplicateMatchResponse] = []
    verification_result: Optional[VerificationResultResponse] = None
    reviews: List[TeacherReviewResponse] = []

    model_config = ConfigDict(from_attributes=True)


# Issuer Schemas
class IssuerCreate(BaseModel):
    name: str
    official_domain: str
    verification_type: IssuerVerificationType = IssuerVerificationType.WEB
    verification_url: Optional[str] = None
    active: bool = True
    configuration_json: Optional[str] = None


class IssuerUpdate(BaseModel):
    name: Optional[str] = None
    official_domain: Optional[str] = None
    verification_type: Optional[IssuerVerificationType] = None
    verification_url: Optional[str] = None
    active: Optional[bool] = None
    configuration_json: Optional[str] = None


class IssuerResponse(BaseModel):
    id: str
    name: str
    official_domain: str
    verification_type: IssuerVerificationType
    verification_url: Optional[str] = None
    active: bool
    configuration_json: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Audit Log Schemas
class AuditLogResponse(BaseModel):
    id: str
    actor_user_id: Optional[str] = None
    actor_name: Optional[str] = None
    action: str
    entity_type: str
    entity_id: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    ip_hash: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Stats
class PlatformStatsResponse(BaseModel):
    total_submissions: int
    processing: int
    verified: int
    needs_review: int
    failed: int
    unverifiable: int
    total_issuers: int
    active_students: int


# Batch Analysis Schemas
class BatchAnalysisResponse(BaseModel):
    id: str
    user_id: str
    original_filename: str
    file_size: int
    sha256: str
    status: str
    total_rows: int
    processed_rows: int
    verdict_counts: Optional[Dict[str, int]] = None
    error_message: Optional[str] = None
    result_ready: bool = False
    created_at: datetime
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
