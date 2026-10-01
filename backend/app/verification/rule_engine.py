from typing import List, Tuple
from app.models import SubmissionStatus, AnomalySeverity, IssuerVerificationStatus
from app.anomaly.rules import AnomalyItem


class FinalStatusEvaluation:
    def __init__(
        self,
        final_status: SubmissionStatus,
        confidence: float,
        reason_summary: str,
        reasons: List[str]
    ):
        self.final_status = final_status
        self.confidence = confidence
        self.reason_summary = reason_summary
        self.reasons = reasons


class VerificationRuleEngine:
    """
    Deterministic rule engine that integrates all verification signals to produce
    an authoritative decision: VERIFIED, REVIEW, FAILED, or UNVERIFIABLE.
    """

    def evaluate(
        self,
        issuer_verification_status: str,
        identity_match_level: str,
        anomalies: List[AnomalyItem],
        file_integrity_pass: bool,
        duplicate_detected: bool,
        qr_verification_status: str
    ) -> FinalStatusEvaluation:
        reasons: List[str] = []
        has_critical = any(a.severity == AnomalySeverity.CRITICAL for a in anomalies)
        has_high = any(a.severity == AnomalySeverity.HIGH for a in anomalies)
        has_medium = any(a.severity == AnomalySeverity.MEDIUM for a in anomalies)

        # 1. File Integrity Failure (File changed after verification or corrupted)
        if not file_integrity_pass:
            reasons.append("Critical file integrity verification failure; file hash mismatch.")
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.REVIEW,
                confidence=0.99,
                reason_summary="Document integrity check failed. The file on disk does not match the upload hash.",
                reasons=reasons
            )

        # 2. Issuer authoritative records confirmed INVALID (does not exist or revoked)
        if issuer_verification_status == IssuerVerificationStatus.INVALID.value:
            reasons.append("Authoritative issuer records explicitly declare this certificate ID invalid or revoked.")
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.FAILED,
                confidence=0.95,
                reason_summary="Issuer confirmed certificate does not exist or has been revoked.",
                reasons=reasons
            )

        # 3. Recipient Mismatch (Belongs to someone else or identity does not match submitting student)
        if identity_match_level == "MISMATCH":
            reasons.append("Authoritative recipient identity does not match the submitting student.")
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.REVIEW,
                confidence=0.92,
                reason_summary="Student identity does not match verified certificate recipient. Sent to teacher for manual review.",
                reasons=reasons
            )

        # 4. Duplicate checks
        if duplicate_detected:
            reasons.append("Certificate ID or exact file already exists in another student's submission.")
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.REVIEW,
                confidence=0.90,
                reason_summary="Potential duplicate submission detected. Flagged for teacher review.",
                reasons=reasons
            )

        # 5. Untrusted QR Domain or QR Redirect to unexpected domain
        qr_anomalies = [a for a in anomalies if a.rule_code in ["A003", "A004"]]
        if qr_anomalies:
            for qa in qr_anomalies:
                reasons.append(qa.description)
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.REVIEW,
                confidence=0.88,
                reason_summary="QR verification failed domain trust validation. Requires human inspection.",
                reasons=reasons
            )

        # 6. Issuer Verification Unavailable / Issuer not in registry
        if issuer_verification_status in [IssuerVerificationStatus.UNAVAILABLE.value, IssuerVerificationStatus.ERROR.value, "NOT_PERFORMED"]:
            reasons.append("Official issuer verification mechanism was unavailable or issuer is unlisted.")
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.UNVERIFIABLE,
                confidence=0.50,
                reason_summary="Cannot verify certificate with authoritative issuer at this time. Insufficient evidence to establish authenticity.",
                reasons=reasons
            )

        # 7. Other Critical or High Anomalies
        if has_critical or has_high:
            for a in anomalies:
                if a.severity in [AnomalySeverity.CRITICAL, AnomalySeverity.HIGH]:
                    reasons.append(f"[{a.severity.value}] {a.title}: {a.description}")
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.REVIEW,
                confidence=0.75,
                reason_summary=f"Detected {len(reasons)} significant anomalies requiring teacher inspection.",
                reasons=reasons
            )

        # 8. All Checks Pass: Trusted issuer VALID + Recipient Matches + Integrity Pass + No Critical/High Anomalies
        if (
            issuer_verification_status == IssuerVerificationStatus.VALID.value
            and identity_match_level in ["EXACT", "HIGH_CONFIDENCE"]
            and not has_critical
            and not has_high
            and file_integrity_pass
        ):
            summary = "Certificate successfully verified against official issuer records with matching recipient identity."
            reasons.append("Issuer confirmed certificate authenticity.")
            reasons.append("Recipient identity matches student records.")
            reasons.append("Document integrity and cryptographic hash validated.")
            if has_medium:
                reasons.append("Minor non-critical warnings noted.")
            return FinalStatusEvaluation(
                final_status=SubmissionStatus.VERIFIED,
                confidence=0.98,
                reason_summary=summary,
                reasons=reasons
            )

        # Fallback to Review
        reasons.append("Ambiguous signals detected across verification pipelines.")
        return FinalStatusEvaluation(
            final_status=SubmissionStatus.REVIEW,
            confidence=0.60,
            reason_summary="Verification signals are inconclusive. Sent to teacher for manual review.",
            reasons=reasons
        )


verification_rule_engine = VerificationRuleEngine()
