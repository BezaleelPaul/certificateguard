import json
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from app.models import AnomalySeverity, IssuerVerificationStatus


class AnomalyItem(BaseModel):
    rule_code: str
    severity: AnomalySeverity
    title: str
    description: str
    evidence: Optional[Dict[str, Any]] = None
    confidence: float = 1.0


class VerificationContext(BaseModel):
    submission_id: str
    student_id: str
    student_name: str
    file_sha256: str
    current_file_sha256: Optional[str] = None
    extracted_cert_id: Optional[str] = None
    extracted_recipient: Optional[str] = None
    extracted_course: Optional[str] = None
    extracted_issue_date: Optional[str] = None
    extracted_expiry_date: Optional[str] = None
    extracted_qr_url: Optional[str] = None
    qr_hostname: Optional[str] = None
    qr_redirect_hostname: Optional[str] = None
    issuer_name: Optional[str] = None
    issuer_domain: Optional[str] = None
    issuer_requires_qr: bool = True
    issuer_verification_status: Optional[str] = None
    issuer_returned_cert_id: Optional[str] = None
    issuer_returned_recipient: Optional[str] = None
    issuer_returned_course: Optional[str] = None
    identity_match_level: Optional[str] = None
    duplicate_matches: List[Dict[str, Any]] = []
    forensic_signal: Optional[str] = None
    forensic_findings: List[str] = []
    synthetic_signal: Optional[str] = None
    qr_is_ssrf_safe: bool = True
    qr_ssrf_reason: Optional[str] = None
    digital_signature_status: Optional[str] = None
    model_config = {"arbitrary_types_allowed": True}


class AnomalyRule:
    rule_code: str
    severity: AnomalySeverity
    title: str

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        raise NotImplementedError


# A001: Certificate ID missing
class RuleA001CertificateIdMissing(AnomalyRule):
    rule_code = "A001"
    severity = AnomalySeverity.HIGH
    title = "Certificate ID Missing"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if not ctx.extracted_cert_id:
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description="Unable to detect or extract a unique certificate ID from the document.",
                evidence={"extracted_cert_id": None}
            )
        return None


# A002: QR missing when issuer normally requires one
class RuleA002QRMissing(AnomalyRule):
    rule_code = "A002"
    severity = AnomalySeverity.MEDIUM
    title = "QR Code Missing"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.issuer_requires_qr and not ctx.extracted_qr_url:
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description="Issuer typically requires a verifiable QR code, but none was detected in this document.",
                evidence={"issuer": ctx.issuer_name, "qr_detected": False}
            )
        return None


# A003: QR domain not trusted
class RuleA003QRDomainUntrusted(AnomalyRule):
    rule_code = "A003"
    severity = AnomalySeverity.HIGH
    title = "QR Domain Not Trusted"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.extracted_qr_url and ctx.qr_hostname:
            if ctx.issuer_domain and ctx.qr_hostname != ctx.issuer_domain and not ctx.qr_hostname.endswith("." + ctx.issuer_domain):
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"QR destination domain '{ctx.qr_hostname}' does not match official registered issuer domain '{ctx.issuer_domain}'.",
                    evidence={"qr_hostname": ctx.qr_hostname, "approved_domain": ctx.issuer_domain}
                )
        return None


# A004: QR redirects to unexpected domain
class RuleA004QRRedirectUnexpected(AnomalyRule):
    rule_code = "A004"
    severity = AnomalySeverity.HIGH
    title = "QR Redirects to Unexpected Domain"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.qr_redirect_hostname and ctx.issuer_domain:
            if ctx.qr_redirect_hostname != ctx.issuer_domain and not ctx.qr_redirect_hostname.endswith("." + ctx.issuer_domain):
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"QR link initiated redirect to unexpected unapproved domain '{ctx.qr_redirect_hostname}'.",
                    evidence={"redirect_hostname": ctx.qr_redirect_hostname, "approved_domain": ctx.issuer_domain}
                )
        return None


# A005: Issuer verification unavailable
class RuleA005IssuerVerificationUnavailable(AnomalyRule):
    rule_code = "A005"
    severity = AnomalySeverity.MEDIUM
    title = "Issuer Verification Unavailable"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.issuer_verification_status == IssuerVerificationStatus.UNAVAILABLE.value:
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description="Unable to reach or query the issuer's verification authority (portal offline or timeout).",
                evidence={"status": ctx.issuer_verification_status}
            )
        return None


# A006: Certificate ID does not exist
class RuleA006CertificateIdDoesNotExist(AnomalyRule):
    rule_code = "A006"
    severity = AnomalySeverity.CRITICAL
    title = "Certificate ID Does Not Exist"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.issuer_verification_status == IssuerVerificationStatus.INVALID.value:
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description="Issuer authoritative records confirm this certificate ID does not exist or has been revoked.",
                evidence={"certificate_id": ctx.extracted_cert_id}
            )
        return None


# A007: Certificate ID exists but recipient differs
class RuleA007RecipientDiffersFromIssuer(AnomalyRule):
    rule_code = "A007"
    severity = AnomalySeverity.CRITICAL
    title = "Certificate Belongs to Different Recipient"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.issuer_returned_recipient and ctx.extracted_recipient:
            from app.verification.identity import identity_matcher
            match = identity_matcher.compare(ctx.issuer_returned_recipient, ctx.extracted_recipient)
            if match.match_level.value == "MISMATCH":
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"Issuer records list recipient as '{ctx.issuer_returned_recipient}', whereas certificate states '{ctx.extracted_recipient}'.",
                    evidence={"issuer_recipient": ctx.issuer_returned_recipient, "extracted_recipient": ctx.extracted_recipient}
                )
        return None


# A008: Certificate ID exists but course differs
class RuleA008CourseDiffers(AnomalyRule):
    rule_code = "A008"
    severity = AnomalySeverity.HIGH
    title = "Course or Program Mismatch"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.issuer_returned_course and ctx.extracted_course:
            ic = ctx.issuer_returned_course.lower().strip()
            ec = ctx.extracted_course.lower().strip()
            if ic not in ec and ec not in ic:
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"Issuer records list course '{ctx.issuer_returned_course}' but certificate document lists '{ctx.extracted_course}'.",
                    evidence={"issuer_course": ctx.issuer_returned_course, "extracted_course": ctx.extracted_course}
                )
        return None


# A009: Submitted name differs from verified recipient
class RuleA009StudentNotRecipient(AnomalyRule):
    rule_code = "A009"
    severity = AnomalySeverity.HIGH
    title = "Student Identity Mismatch"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        target_name = ctx.issuer_returned_recipient or ctx.extracted_recipient
        if target_name and ctx.student_name:
            from app.verification.identity import identity_matcher
            match = identity_matcher.compare(ctx.student_name, target_name)
            if match.match_level.value == "MISMATCH":
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"The submitting student '{ctx.student_name}' does not match the verified recipient '{target_name}'.",
                    evidence={"student_name": ctx.student_name, "recipient_name": target_name, "similarity": match.similarity_score}
                )
        return None


# A010: Certificate ID already submitted by another student
class RuleA010CertIdDuplicateAnotherStudent(AnomalyRule):
    rule_code = "A010"
    severity = AnomalySeverity.CRITICAL
    title = "Certificate ID Submitted by Another Student"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        for match in ctx.duplicate_matches:
            if match.get("match_type") == "CERTIFICATE_ID" and match.get("other_student_id") != ctx.student_id:
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"Certificate ID '{ctx.extracted_cert_id}' was previously submitted by student ID '{match.get('other_student_id')}'.",
                    evidence=match
                )
        return None


# A011: Exact file duplicate
class RuleA011ExactFileDuplicate(AnomalyRule):
    rule_code = "A011"
    severity = AnomalySeverity.HIGH
    title = "Exact Duplicate File"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        for match in ctx.duplicate_matches:
            if match.get("match_type") == "EXACT_HASH":
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"This exact file (SHA-256 {ctx.file_sha256[:16]}...) has already been submitted in submission '{match.get('matched_submission_id')}'.",
                    evidence=match
                )
        return None


# A012: Perceptual duplicate
class RuleA012PerceptualDuplicate(AnomalyRule):
    rule_code = "A012"
    severity = AnomalySeverity.MEDIUM
    title = "Perceptual Visual Duplicate"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        for match in ctx.duplicate_matches:
            if match.get("match_type") == "PERCEPTUAL_SIMILARITY":
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"Visual layout and structure closely mirror prior submission '{match.get('matched_submission_id')}' (Similarity: {match.get('similarity', 0):.2f}).",
                    evidence=match
                )
        return None


# A013: File changed after verification
class RuleA013FileChangedAfterVerification(AnomalyRule):
    rule_code = "A013"
    severity = AnomalySeverity.CRITICAL
    title = "File Tampered After Verification"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.current_file_sha256 and ctx.current_file_sha256 != ctx.file_sha256:
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description="CRITICAL INTEGRITY FAILURE: The physical file bytes changed after upload/verification.",
                evidence={"original_sha256": ctx.file_sha256, "current_sha256": ctx.current_file_sha256}
            )
        return None


# A014: Suspicious document forensic signal
class RuleA014ForensicSignalSuspicious(AnomalyRule):
    rule_code = "A014"
    severity = AnomalySeverity.MEDIUM
    title = "Suspicious Document Forensic Artifacts"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.forensic_signal == "SUSPICIOUS":
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description=f"Document forensics identified anomalies: {'; '.join(ctx.forensic_findings)}",
                evidence={"findings": ctx.forensic_findings}
            )
        return None


# A015: Synthetic-document detector suspicious
class RuleA015SyntheticDocumentSuspicious(AnomalyRule):
    rule_code = "A015"
    severity = AnomalySeverity.LOW
    title = "Synthetic Media Signal Flagged"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.synthetic_signal == "SUSPICIOUS":
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description="Supporting AI/synthetic-media analysis indicated potential digital generation markers.",
                evidence={"signal": ctx.synthetic_signal}
            )
        return None


# A016: Issuer verification response inconsistent with extracted data
class RuleA016IssuerExtractedInconsistency(AnomalyRule):
    rule_code = "A016"
    severity = AnomalySeverity.HIGH
    title = "Issuer Data Inconsistent With Extracted Fields"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.issuer_returned_cert_id and ctx.extracted_cert_id:
            if ctx.issuer_returned_cert_id.strip().lower() != ctx.extracted_cert_id.strip().lower():
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"Extracted Certificate ID '{ctx.extracted_cert_id}' does not match issuer verified ID '{ctx.issuer_returned_cert_id}'.",
                    evidence={"extracted": ctx.extracted_cert_id, "issuer": ctx.issuer_returned_cert_id}
                )
        return None


# A017: Unusual certificate ID format
class RuleA017UnusualCertIdFormat(AnomalyRule):
    rule_code = "A017"
    severity = AnomalySeverity.LOW
    title = "Unusual Certificate ID Format"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.extracted_cert_id:
            # If cert id is trivially short or has weird non-standard characters
            cid = ctx.extracted_cert_id.strip()
            if len(cid) < 4 or bool(re.search(r"[\s<>{}\\]", cid)):
                return AnomalyItem(
                    rule_code=self.rule_code,
                    severity=self.severity,
                    title=self.title,
                    description=f"Certificate ID '{cid}' does not match conventional alphanumeric identifier structures.",
                    evidence={"certificate_id": cid}
                )
        return None


# A018: Certificate date inconsistency
class RuleA018DateInconsistency(AnomalyRule):
    rule_code = "A018"
    severity = AnomalySeverity.MEDIUM
    title = "Issue Date Inconsistency"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.extracted_issue_date:
            try:
                # Try simple year extraction
                year_match = re.search(r"\b(19\d{2}|20\d{2})\b", ctx.extracted_issue_date)
                if year_match:
                    year = int(year_match.group(1))
                    current_year = datetime.now(timezone.utc).year
                    if year > current_year + 1 or year < 1980:
                        return AnomalyItem(
                            rule_code=self.rule_code,
                            severity=self.severity,
                            title=self.title,
                            description=f"Extracted issue date '{ctx.extracted_issue_date}' specifies an implausible year ({year}).",
                            evidence={"issue_date": ctx.extracted_issue_date, "year": year}
                        )
            except Exception:
                pass
        return None


# A019: Expiry inconsistency
class RuleA019ExpiryInconsistency(AnomalyRule):
    rule_code = "A019"
    severity = AnomalySeverity.MEDIUM
    title = "Certificate Expired Prior to Submission"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.extracted_expiry_date:
            try:
                year_match = re.search(r"\b(19\d{2}|20\d{2})\b", ctx.extracted_expiry_date)
                if year_match:
                    year = int(year_match.group(1))
                    current_year = datetime.now(timezone.utc).year
                    if year < current_year - 5:
                        return AnomalyItem(
                            rule_code=self.rule_code,
                            severity=self.severity,
                            title=self.title,
                            description=f"Certificate expiration date '{ctx.extracted_expiry_date}' indicates the credential has lapsed.",
                            evidence={"expiry_date": ctx.extracted_expiry_date}
                        )
            except Exception:
                pass
        return None


# A020: Multiple submissions with unusually similar certificates
class RuleA020MultipleSimilarSubmissions(AnomalyRule):
    rule_code = "A020"
    severity = AnomalySeverity.MEDIUM
    title = "Cluster of Similar Submissions Detected"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        for match in ctx.duplicate_matches:
            if match.get("match_type") == "OCR_SIMILARITY" and match.get("similarity", 0) > 0.85:
                if match.get("other_student_id") != ctx.student_id:
                    return AnomalyItem(
                        rule_code=self.rule_code,
                        severity=self.severity,
                        title=self.title,
                        description=f"Textual similarity of {match.get('similarity'):.0%} with another student's submission '{match.get('matched_submission_id')}'.",
                        evidence=match
                    )
        return None


# A021: Server-Side Request Forgery (SSRF) Attempt
class RuleA021SSRFAttempt(AnomalyRule):
    rule_code = "A021"
    severity = AnomalySeverity.CRITICAL
    title = "Server-Side Request Forgery (SSRF) Attempt Detected"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if not ctx.qr_is_ssrf_safe:
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description=f"Destination URL in certificate triggers SSRF protection: {ctx.qr_ssrf_reason or 'Forbidden target'}",
                evidence={"qr_url": ctx.extracted_qr_url, "reason": ctx.qr_ssrf_reason}
            )
        return None


# A022: Cryptographic Digital Signature Tampered
class RuleA022DigitalSignatureTampered(AnomalyRule):
    rule_code = "A022"
    severity = AnomalySeverity.CRITICAL
    title = "Cryptographic Digital Signature Tampered"

    def evaluate(self, ctx: VerificationContext) -> Optional[AnomalyItem]:
        if ctx.digital_signature_status == "TAMPERED":
            return AnomalyItem(
                rule_code=self.rule_code,
                severity=self.severity,
                title=self.title,
                description="The cryptographic digital signature on this PDF has been invalidated or unauthenticated bytes were appended after the signed byte range.",
                evidence={"digital_signature_status": ctx.digital_signature_status}
            )
        return None


ALL_ANOMALY_RULES: List[AnomalyRule] = [
    RuleA001CertificateIdMissing(),
    RuleA002QRMissing(),
    RuleA003QRDomainUntrusted(),
    RuleA004QRRedirectUnexpected(),
    RuleA005IssuerVerificationUnavailable(),
    RuleA006CertificateIdDoesNotExist(),
    RuleA007RecipientDiffersFromIssuer(),
    RuleA008CourseDiffers(),
    RuleA009StudentNotRecipient(),
    RuleA010CertIdDuplicateAnotherStudent(),
    RuleA011ExactFileDuplicate(),
    RuleA012PerceptualDuplicate(),
    RuleA013FileChangedAfterVerification(),
    RuleA014ForensicSignalSuspicious(),
    RuleA015SyntheticDocumentSuspicious(),
    RuleA016IssuerExtractedInconsistency(),
    RuleA017UnusualCertIdFormat(),
    RuleA018DateInconsistency(),
    RuleA019ExpiryInconsistency(),
    RuleA020MultipleSimilarSubmissions(),
    RuleA021SSRFAttempt(),
    RuleA022DigitalSignatureTampered(),
]
