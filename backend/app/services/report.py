from typing import List, Optional, Dict, Any
from app.models import Submission, ExtractedCertificateData, VerificationResult, Anomaly, DuplicateMatch, IssuerVerification


class EvidenceReportGenerator:
    """
    Generates structured plain-text and dictionary evidence verification reports.
    """

    def generate_text_report(
        self,
        student_name: str,
        submission: Submission,
        extracted: Optional[ExtractedCertificateData],
        issuer_verif: Optional[IssuerVerification],
        verification_result: Optional[VerificationResult],
        anomalies: List[Anomaly],
        duplicate_matches: List[DuplicateMatch],
        approved_domain: Optional[str] = None
    ) -> str:
        cert_name = (extracted.course_name if extracted else None) or "Certificate Document"
        issuer_name = (extracted.issuer_name if extracted else None) or (issuer_verif.issuer.name if issuer_verif and issuer_verif.issuer else "Unknown Issuer")
        cert_id = (extracted.certificate_id if extracted else None) or "N/A"

        lines = [
            "============================================================",
            "             CERTIFICATE VERIFICATION REPORT                ",
            "============================================================",
            f"Student:             {student_name}",
            f"Certificate Course:  {cert_name}",
            f"Issuer:              {issuer_name}",
            f"Certificate ID:      {cert_id}",
            f"Submission ID:       {submission.id}",
            f"Timestamp:           {submission.uploaded_at}",
            "------------------------------------------------------------",
            "FILE INTEGRITY",
            f"SHA-256:             {submission.sha256}",
            f"File Size:           {submission.file_size} bytes",
            f"Status:              {'PASS' if (verification_result and verification_result.document_integrity != 'FAIL') else 'FAIL'}",
            "",
            "QR VERIFICATION",
            f"Status:              {verification_result.qr_verification if verification_result else 'NOT_PERFORMED'}",
            f"Extracted URL:       {(extracted.qr_url if extracted else None) or 'None'}",
            f"Domain:              {approved_domain or 'N/A'}",
            "",
            "ISSUER VERIFICATION",
            f"Status:              {issuer_verif.verification_status if issuer_verif else 'NOT_PERFORMED'}",
            f"Method:              {issuer_verif.verification_method if issuer_verif else 'N/A'}",
            f"Verified Recipient:  {(issuer_verif.recipient_returned if issuer_verif else None) or 'N/A'}",
            f"Verified Course:     {(issuer_verif.course_returned if issuer_verif else None) or 'N/A'}",
            "",
            "IDENTITY MATCH",
            f"Status:              {verification_result.identity_verification if verification_result else 'NOT_PERFORMED'}",
            f"Submitted Student:   {student_name}",
            f"Matched Recipient:   {(issuer_verif.recipient_returned if issuer_verif else None) or (extracted.recipient_name if extracted else 'N/A')}",
            "",
            "DUPLICATE CHECK",
            f"Status:              {'FLAGGED' if duplicate_matches else 'PASS'}",
            f"Duplicate Matches:   {len(duplicate_matches)}",
            "",
            "DOCUMENT FORENSICS",
            f"Status:              {verification_result.document_integrity if verification_result else 'NO_STRONG_SIGNAL'}",
            "",
            "SYNTHETIC DOCUMENT CHECK",
            f"Status:              {verification_result.synthetic_media_signal if verification_result else 'INCONCLUSIVE'}",
            f"Note:                AI detection is supporting evidence only, not proof of authenticity.",
            "",
            "ANOMALIES DETECTED"
        ]

        if not anomalies:
            lines.append("None")
        else:
            for idx, a in enumerate(anomalies, 1):
                lines.append(f"{idx}. [{a.severity}] {a.title}: {a.description}")

        lines.extend([
            "------------------------------------------------------------",
            "SYSTEM RESULT",
            f"FINAL STATUS:        {verification_result.final_status if verification_result else submission.status}",
            f"CONFIDENCE:          {(verification_result.confidence * 100):.1f}%" if verification_result else "N/A",
            f"SUMMARY:             {verification_result.reason_summary if verification_result else 'N/A'}",
            "============================================================"
        ])

        return "\n".join(lines)


report_generator = EvidenceReportGenerator()
