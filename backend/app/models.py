from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
import uuid
from app.database import Base


def generate_uuid():
    return str(uuid.uuid4())


class UserRole(str, enum.Enum):
    STUDENT = "STUDENT"
    TEACHER = "TEACHER"
    ADMIN = "ADMIN"


class SubmissionStatus(str, enum.Enum):
    PROCESSING = "PROCESSING"
    VERIFIED = "VERIFIED"
    REVIEW = "REVIEW"
    FAILED = "FAILED"
    UNVERIFIABLE = "UNVERIFIABLE"
    ERROR = "ERROR"


class IssuerVerificationType(str, enum.Enum):
    API = "API"
    WEB = "WEB"
    MANUAL = "MANUAL"
    NONE = "NONE"


class IssuerVerificationStatus(str, enum.Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class AnomalySeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DuplicateMatchType(str, enum.Enum):
    EXACT_HASH = "EXACT_HASH"
    PERCEPTUAL_SIMILARITY = "PERCEPTUAL_SIMILARITY"
    CERTIFICATE_ID = "CERTIFICATE_ID"
    OCR_SIMILARITY = "OCR_SIMILARITY"


class TeacherReviewDecision(str, enum.Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REQUEST_EVIDENCE = "REQUEST_EVIDENCE"


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default=UserRole.STUDENT.value)
    student_id = Column(String(36), ForeignKey("students.id", use_alter=True, name="fk_user_student"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    student_profile = relationship("Student", foreign_keys=[student_id], back_populates="user_account")
    reviews = relationship("TeacherReview", back_populates="teacher")
    audit_logs = relationship("AuditLog", back_populates="actor")


class Student(Base):
    __tablename__ = "students"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), nullable=True)
    student_identifier = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    department = Column(String(100), nullable=False, default="Computer Science")
    section = Column(String(50), nullable=False, default="A")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user_account = relationship("User", foreign_keys=[User.student_id], back_populates="student_profile")
    submissions = relationship("Submission", back_populates="student", cascade="all, delete-orphan")


class Submission(Base):
    __tablename__ = "submissions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    student_id = Column(String(36), ForeignKey("students.id"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    storage_key = Column(String(255), nullable=False)
    mime_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String(50), nullable=False, default=SubmissionStatus.PROCESSING.value, index=True)
    processing_started_at = Column(DateTime(timezone=True), nullable=True)
    processing_completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    student = relationship("Student", back_populates="submissions")
    extracted_data = relationship("ExtractedCertificateData", back_populates="submission", uselist=False, cascade="all, delete-orphan")
    issuer_verifications = relationship("IssuerVerification", back_populates="submission", cascade="all, delete-orphan")
    anomalies = relationship("Anomaly", back_populates="submission", cascade="all, delete-orphan")
    duplicate_matches = relationship("DuplicateMatch", foreign_keys="DuplicateMatch.submission_id", back_populates="submission", cascade="all, delete-orphan")
    verification_result = relationship("VerificationResult", back_populates="submission", uselist=False, cascade="all, delete-orphan")
    reviews = relationship("TeacherReview", back_populates="submission", cascade="all, delete-orphan")


class ExtractedCertificateData(Base):
    __tablename__ = "extracted_certificate_data"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    submission_id = Column(String(36), ForeignKey("submissions.id"), nullable=False, unique=True, index=True)
    recipient_name = Column(String(255), nullable=True)
    issuer_name = Column(String(255), nullable=True)
    certificate_id = Column(String(255), nullable=True, index=True)
    course_name = Column(String(255), nullable=True)
    issue_date = Column(String(100), nullable=True)
    expiry_date = Column(String(100), nullable=True)
    qr_url = Column(Text, nullable=True)
    raw_ocr_text = Column(Text, nullable=True)
    extraction_confidence = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    submission = relationship("Submission", back_populates="extracted_data")


class Issuer(Base):
    __tablename__ = "issuers"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    official_domain = Column(String(255), unique=True, index=True, nullable=False)
    verification_type = Column(String(50), nullable=False, default=IssuerVerificationType.WEB.value)
    verification_url = Column(Text, nullable=True)
    active = Column(Boolean, nullable=False, default=True)
    configuration_json = Column(Text, nullable=True)  # JSON config e.g. selectors, headers, API keys
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    verifications = relationship("IssuerVerification", back_populates="issuer")


class IssuerVerification(Base):
    __tablename__ = "issuer_verifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    submission_id = Column(String(36), ForeignKey("submissions.id"), nullable=False, index=True)
    issuer_id = Column(String(36), ForeignKey("issuers.id"), nullable=True)
    verification_method = Column(String(50), nullable=False)  # API, WEB, MOCK, MANUAL
    verification_url = Column(Text, nullable=True)
    certificate_id_submitted = Column(String(255), nullable=True)
    certificate_id_returned = Column(String(255), nullable=True)
    recipient_returned = Column(String(255), nullable=True)
    course_returned = Column(String(255), nullable=True)
    status_returned = Column(String(100), nullable=True)
    raw_evidence = Column(Text, nullable=True)  # JSON or text capture of evidence
    verification_status = Column(String(50), nullable=False, default=IssuerVerificationStatus.UNAVAILABLE.value)
    verified_at = Column(DateTime(timezone=True), server_default=func.now())
    error_message = Column(Text, nullable=True)

    submission = relationship("Submission", back_populates="issuer_verifications")
    issuer = relationship("Issuer", back_populates="verifications")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    submission_id = Column(String(36), ForeignKey("submissions.id"), nullable=False, index=True)
    type = Column(String(50), nullable=False)  # A001, A002, etc.
    severity = Column(String(50), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)  # JSON details of anomaly
    confidence = Column(Float, nullable=False, default=1.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    submission = relationship("Submission", back_populates="anomalies")


class DuplicateMatch(Base):
    __tablename__ = "duplicate_matches"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    submission_id = Column(String(36), ForeignKey("submissions.id"), nullable=False, index=True)
    matched_submission_id = Column(String(36), ForeignKey("submissions.id"), nullable=False, index=True)
    match_type = Column(String(50), nullable=False)  # EXACT_HASH, PERCEPTUAL_SIMILARITY, CERTIFICATE_ID, OCR_SIMILARITY
    similarity = Column(Float, nullable=False, default=1.0)
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    submission = relationship("Submission", foreign_keys=[submission_id], back_populates="duplicate_matches")
    matched_submission = relationship("Submission", foreign_keys=[matched_submission_id])


class VerificationResult(Base):
    __tablename__ = "verification_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    submission_id = Column(String(36), ForeignKey("submissions.id"), nullable=False, unique=True, index=True)

    issuer_verification = Column(String(50), nullable=False, default="NOT_PERFORMED")
    identity_verification = Column(String(50), nullable=False, default="NOT_PERFORMED")
    qr_verification = Column(String(50), nullable=False, default="NOT_PERFORMED")
    certificate_id_verification = Column(String(50), nullable=False, default="NOT_PERFORMED")
    document_integrity = Column(String(50), nullable=False, default="NOT_PERFORMED")
    duplicate_check = Column(String(50), nullable=False, default="NOT_PERFORMED")
    anomaly_check = Column(String(50), nullable=False, default="NOT_PERFORMED")
    synthetic_media_signal = Column(String(50), nullable=False, default="INCONCLUSIVE")

    final_status = Column(String(50), nullable=False, default=SubmissionStatus.PROCESSING.value)
    confidence = Column(Float, nullable=False, default=0.0)
    reason_summary = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    submission = relationship("Submission", back_populates="verification_result")


class TeacherReview(Base):
    __tablename__ = "teacher_reviews"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    submission_id = Column(String(36), ForeignKey("submissions.id"), nullable=False, index=True)
    teacher_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    decision = Column(String(50), nullable=False)  # APPROVE, REJECT, REQUEST_EVIDENCE
    reason = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    submission = relationship("Submission", back_populates="reviews")
    teacher = relationship("User", back_populates="reviews")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    actor_user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(100), nullable=False)
    entity_id = Column(String(36), nullable=False, index=True)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    ip_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    actor = relationship("User", back_populates="audit_logs")
