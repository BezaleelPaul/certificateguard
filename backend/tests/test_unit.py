import pytest
from pathlib import Path
from app.security.validation import compute_sha256, validate_file_upload, FileValidationError
from app.verification.identity import identity_matcher, IdentityMatchLevel
from app.extraction.qr import qr_extractor
from app.extraction.certificate_data import certificate_extractor
from app.verification.duplicate import duplicate_detector
from app.anomaly.rules import (
    VerificationContext,
    RuleA001CertificateIdMissing,
    RuleA003QRDomainUntrusted,
    RuleA006CertificateIdDoesNotExist,
    RuleA007RecipientDiffersFromIssuer,
    RuleA009StudentNotRecipient,
    RuleA010CertIdDuplicateAnotherStudent,
    RuleA011ExactFileDuplicate,
    RuleA013FileChangedAfterVerification
)
from app.anomaly.engine import anomaly_engine
from app.verification.rule_engine import verification_rule_engine
from app.models import SubmissionStatus, AnomalySeverity, IssuerVerificationStatus


def test_hash_calculation():
    data = b"Official University Certificate Content 12345"
    hash1 = compute_sha256(data)
    hash2 = compute_sha256(data)
    assert hash1 == hash2
    assert len(hash1) == 64
    assert hash1 != compute_sha256(b"Tampered Content")


def test_name_normalization_and_identity_matching():
    # Exact normalized match
    res1 = identity_matcher.compare("Bezaleel Paul", "BEZALEEL PAUL")
    assert res1.match_level == IdentityMatchLevel.EXACT
    assert res1.similarity_score == 1.0

    # Token reordering match
    res2 = identity_matcher.compare("Paul Bezaleel", "Bezaleel Paul")
    assert res2.match_level in [IdentityMatchLevel.EXACT, IdentityMatchLevel.HIGH_CONFIDENCE]

    # Clear mismatch
    res3 = identity_matcher.compare("Bezaleel Paul", "Rahul Kumar")
    assert res3.match_level == IdentityMatchLevel.MISMATCH

    # Middle name / initial variation
    res4 = identity_matcher.compare("Bezaleel K. Paul", "Bezaleel Paul")
    assert res4.match_level == IdentityMatchLevel.HIGH_CONFIDENCE


def test_qr_domain_validation():
    # Valid official domain
    assert qr_extractor.validate_domain("example.edu", "example.edu") is True
    assert qr_extractor.validate_domain("verify.example.edu", "example.edu") is True

    # Malicious domain suffixes / spoofing attempts
    assert qr_extractor.validate_domain("example.edu.fake.io", "example.edu") is False
    assert qr_extractor.validate_domain("fake-example.edu", "example.edu") is False
    assert qr_extractor.validate_domain("example.edu.attacker.com", "example.edu") is False
    assert qr_extractor.validate_domain("notexample.edu", "example.edu") is False


def test_certificate_data_extraction():
    sample_text = """
    EXAMPLE UNIVERSITY
    Certificate of Completion
    This is to certify that
    Bezaleel Paul
    has successfully completed the course
    Machine Learning Certificate
    Issue Date: 2025-07-20
    Certificate ID: CERT-1002
    """
    extracted = certificate_extractor.extract(sample_text)
    assert extracted.certificate_id == "CERT-1002"
    assert extracted.recipient_name == "Bezaleel Paul"
    assert extracted.course_name == "Machine Learning Certificate"
    assert extracted.extraction_confidence > 0.5


def test_duplicate_detection_algorithms():
    text1 = "This is a machine learning certificate issued to Bezaleel Paul by Example University."
    text2 = "This is a machine learning certificate issued to Bezaleel Paul by Example University."
    text3 = "Unrelated driving license document issued in California."

    sim_identical = duplicate_detector.compute_text_similarity(text1, text2)
    sim_unrelated = duplicate_detector.compute_text_similarity(text1, text3)

    assert sim_identical == 1.0
    assert sim_unrelated < 0.2


def test_anomaly_rules_evaluation():
    # Test A001: Missing ID
    rule_a001 = RuleA001CertificateIdMissing()
    ctx1 = VerificationContext(
        submission_id="s1",
        student_id="st1",
        student_name="Bezaleel Paul",
        file_sha256="abc",
        extracted_cert_id=None
    )
    assert rule_a001.evaluate(ctx1) is not None

    # Test A003: Untrusted QR Domain
    rule_a003 = RuleA003QRDomainUntrusted()
    ctx2 = VerificationContext(
        submission_id="s2",
        student_id="st1",
        student_name="Bezaleel Paul",
        file_sha256="abc",
        extracted_qr_url="https://fake-example.edu/verify",
        qr_hostname="fake-example.edu",
        issuer_domain="example.edu"
    )
    assert rule_a003.evaluate(ctx2) is not None

    # Test A006: Invalid Certificate ID
    rule_a006 = RuleA006CertificateIdDoesNotExist()
    ctx3 = VerificationContext(
        submission_id="s3",
        student_id="st1",
        student_name="Bezaleel Paul",
        file_sha256="abc",
        extracted_cert_id="CERT-1003",
        issuer_verification_status=IssuerVerificationStatus.INVALID.value
    )
    assert rule_a006.evaluate(ctx3) is not None

    # Test A013: File Changed After Verification
    rule_a013 = RuleA013FileChangedAfterVerification()
    ctx4 = VerificationContext(
        submission_id="s4",
        student_id="st1",
        student_name="Bezaleel Paul",
        file_sha256="original_hash_123",
        current_file_sha256="altered_tampered_hash_456"
    )
    anom_tampered = rule_a013.evaluate(ctx4)
    assert anom_tampered is not None
    assert anom_tampered.severity == AnomalySeverity.CRITICAL


def test_final_status_rule_engine():
    # Case 1: Verified
    eval1 = verification_rule_engine.evaluate(
        issuer_verification_status="VALID",
        identity_match_level="EXACT",
        anomalies=[],
        file_integrity_pass=True,
        duplicate_detected=False,
        qr_verification_status="PASS"
    )
    assert eval1.final_status == SubmissionStatus.VERIFIED

    # Case 2: Issuer Invalid -> FAILED
    eval2 = verification_rule_engine.evaluate(
        issuer_verification_status="INVALID",
        identity_match_level="EXACT",
        anomalies=[],
        file_integrity_pass=True,
        duplicate_detected=False,
        qr_verification_status="PASS"
    )
    assert eval2.final_status == SubmissionStatus.FAILED

    # Case 3: Recipient Mismatch -> REVIEW
    eval3 = verification_rule_engine.evaluate(
        issuer_verification_status="VALID",
        identity_match_level="MISMATCH",
        anomalies=[],
        file_integrity_pass=True,
        duplicate_detected=False,
        qr_verification_status="PASS"
    )
    assert eval3.final_status == SubmissionStatus.REVIEW

    # Case 4: Issuer Unavailable -> UNVERIFIABLE
    eval4 = verification_rule_engine.evaluate(
        issuer_verification_status="UNAVAILABLE",
        identity_match_level="EXACT",
        anomalies=[],
        file_integrity_pass=True,
        duplicate_detected=False,
        qr_verification_status="PASS"
    )
    assert eval4.final_status == SubmissionStatus.UNVERIFIABLE


def test_file_upload_validation_security():
    # Valid PDF
    valid_pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n164\n%%EOF"
    is_valid, detected, ext = validate_file_upload("cert.pdf", valid_pdf_bytes, "application/pdf")
    assert is_valid is True
    assert detected == "pdf"

    # Malicious extension attempt
    with pytest.raises(FileValidationError):
        validate_file_upload("cert.exe", b"%PDF-1.4...", "application/x-msdownload")

    # Mismatched magic bytes (executable disguised as pdf)
    with pytest.raises(FileValidationError):
        validate_file_upload("exploit.pdf", b"MZ\x90\x00\x03\x00\x00\x00", "application/pdf")


def test_ssrf_guard_protections():
    from app.security.ssrf import validate_url_ssrf, is_safe_url

    # AWS/GCP/Azure Cloud Metadata IPs
    res_metadata = validate_url_ssrf("http://169.254.169.254/latest/meta-data/")
    assert res_metadata.is_safe is False
    assert "metadata" in res_metadata.reason.lower() or "rejected" in res_metadata.reason.lower()

    # RFC 1918 Private IPv4
    assert is_safe_url("http://10.0.0.1/internal-status") is False
    assert is_safe_url("http://192.168.1.100/router-config") is False
    assert is_safe_url("http://172.16.50.4/metrics") is False

    # Loopback IP
    assert is_safe_url("http://127.0.0.1:8000/api/admin") is False
    assert is_safe_url("http://localhost:3000") is False

    # Non-HTTP/HTTPS protocol schemes
    assert is_safe_url("file:///etc/passwd") is False
    assert is_safe_url("gopher://127.0.0.1:70") is False
    assert is_safe_url("ftp://internal.server/file") is False


def test_advanced_name_normalization_variations():
    # Honorifics
    res_title = identity_matcher.compare("Dr. Bezaleel Paul", "Bezaleel Paul")
    assert res_title.match_level == IdentityMatchLevel.EXACT
    assert res_title.similarity_score == 1.0

    # Inverted name format (LastName, FirstName)
    res_inverted = identity_matcher.compare("Paul, Bezaleel", "Bezaleel Paul")
    assert res_inverted.match_level == IdentityMatchLevel.EXACT

    # Academic credentials / suffixes
    res_suffix = identity_matcher.compare("Bezaleel Paul, Ph.D.", "Bezaleel Paul")
    assert res_suffix.match_level == IdentityMatchLevel.EXACT

    # Combined title and suffix
    res_prof = identity_matcher.compare("Prof. Bezaleel Paul, Jr.", "Bezaleel Paul")
    assert res_prof.match_level == IdentityMatchLevel.EXACT

    # Initials matching
    res_initial = identity_matcher.compare("B. Paul", "Bezaleel Paul")
    assert res_initial.match_level == IdentityMatchLevel.HIGH_CONFIDENCE
    assert res_initial.similarity_score > 0.90


def test_pdf_cryptographic_signature_verifier():
    from app.verification.signatures import pdf_signature_verifier

    # 1. Plain unsigned document
    unsigned_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    sig_unsigned = pdf_signature_verifier.verify_bytes(unsigned_pdf)
    assert sig_unsigned.has_signature is False
    assert sig_unsigned.status == "UNSIGNED"

    # 2. Tampered PDF with appended payload past byte range
    # Signature specifies range ending at index 100, but file has 500 extra bytes appended
    base_signed_mock = (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Sig /ByteRange [0 50 80 20] /Contents <010203> >>\nendobj\n%%EOF"
    )
    # Append unauthenticated payload (exploiting incremental update vulnerability)
    tampered_signed_pdf = base_signed_mock + (b"\n% Malicious appended payload altering student name to Eve\n" * 10)
    sig_tampered = pdf_signature_verifier.verify_bytes(tampered_signed_pdf)
    assert sig_tampered.has_signature is True
    assert sig_tampered.status == "TAMPERED"
    assert any("unauthenticated bytes" in r.lower() for r in sig_tampered.tamper_reasons)

