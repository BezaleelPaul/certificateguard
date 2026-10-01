import pytest
from httpx import AsyncClient, ASGITransport
from pathlib import Path
import os
from app.main import app
from app.models import SubmissionStatus
from app.storage import storage_provider
from app.verification.playwright_adapter import PlaywrightIssuerAdapter
from app.models import IssuerVerificationStatus

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "test-fixtures"


@pytest.mark.asyncio
async def test_attack_01_real_certificate_wrong_student(student_auth_headers):
    """Attack 1 — Real certificate belonging to Rahul Kumar, uploaded by Bezaleel Paul -> REVIEW (RECIPIENT_MISMATCH)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with open(FIXTURES_DIR / "wrong_recipient_certificate.pdf", "rb") as f:
            upload_resp = await client.post(
                "/api/submissions",
                files={"file": ("wrong_recipient.pdf", f, "application/pdf")},
                headers=student_auth_headers
            )
        sub_id = upload_resp.json()["id"]
        process_resp = await client.post(f"/api/submissions/{sub_id}/process", headers=student_auth_headers)
        data = process_resp.json()
        assert data["status"] == "REVIEW"
        anomalies = [a["type"] for a in data["anomalies"]]
        assert "A009" in anomalies  # Student not recipient


@pytest.mark.asyncio
async def test_attack_02_fake_qr_domain(student_auth_headers):
    """Attack 2 — Fake QR domain -> REVIEW (UNTRUSTED_QR_DOMAIN)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with open(FIXTURES_DIR / "untrusted_qr_certificate.pdf", "rb") as f:
            upload_resp = await client.post(
                "/api/submissions",
                files={"file": ("untrusted_qr.pdf", f, "application/pdf")},
                headers=student_auth_headers
            )
        sub_id = upload_resp.json()["id"]
        process_resp = await client.post(f"/api/submissions/{sub_id}/process", headers=student_auth_headers)
        data = process_resp.json()
        assert data["status"] == "REVIEW"
        anomalies = [a["type"] for a in data["anomalies"]]
        assert "A003" in anomalies  # QR domain untrusted


@pytest.mark.asyncio
async def test_attack_03_valid_qr_mismatched_cert_id(student_auth_headers):
    """Attack 3 — Valid QR with mismatched certificate ID -> REVIEW."""
    from app.anomaly.rules import VerificationContext, RuleA016IssuerExtractedInconsistency
    rule = RuleA016IssuerExtractedInconsistency()
    ctx = VerificationContext(
        submission_id="s_test",
        student_id="st_test",
        student_name="Bezaleel Paul",
        file_sha256="abc",
        extracted_cert_id="CERT-1002",
        issuer_returned_cert_id="CERT-9999"
    )
    anomaly = rule.evaluate(ctx)
    assert anomaly is not None
    assert anomaly.rule_code == "A016"


@pytest.mark.asyncio
async def test_attack_04_cert_id_exists_recipient_differs():
    """Attack 4 — Certificate ID exists but recipient differs -> REVIEW."""
    from app.anomaly.rules import VerificationContext, RuleA007RecipientDiffersFromIssuer
    rule = RuleA007RecipientDiffersFromIssuer()
    ctx = VerificationContext(
        submission_id="s_test",
        student_id="st_test",
        student_name="Bezaleel Paul",
        file_sha256="abc",
        extracted_recipient="Bezaleel Paul",
        issuer_returned_recipient="Rahul Kumar"
    )
    anomaly = rule.evaluate(ctx)
    assert anomaly is not None
    assert anomaly.rule_code == "A007"


@pytest.mark.asyncio
async def test_attack_05_same_certificate_uploaded_twice(student_auth_headers):
    """Attack 5 — Same certificate uploaded twice -> DUPLICATE detection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First upload
        with open(FIXTURES_DIR / "valid_certificate.pdf", "rb") as f:
            u1 = await client.post("/api/submissions", files={"file": ("v1.pdf", f, "application/pdf")}, headers=student_auth_headers)
        sub1_id = u1.json()["id"]
        await client.post(f"/api/submissions/{sub1_id}/process", headers=student_auth_headers)

        # Second upload of duplicate
        with open(FIXTURES_DIR / "duplicate_certificate.pdf", "rb") as f:
            u2 = await client.post("/api/submissions", files={"file": ("v2.pdf", f, "application/pdf")}, headers=student_auth_headers)
        sub2_id = u2.json()["id"]
        p2 = await client.post(f"/api/submissions/{sub2_id}/process", headers=student_auth_headers)
        data = p2.json()
        assert len(data["duplicate_matches"]) > 0
        match_types = [m["match_type"] for m in data["duplicate_matches"]]
        assert "EXACT_HASH" in match_types


@pytest.mark.asyncio
async def test_attack_06_modified_certificate_similarity():
    """Attack 6 — Visually modified certificate -> OCR_SIMILARITY / PERCEPTUAL_DUPLICATE."""
    from app.verification.duplicate import duplicate_detector
    text_orig = "EXAMPLE UNIVERSITY Certificate of Completion Awarded to Bezaleel Paul for Machine Learning"
    text_mod = "EXAMPLE UNIVERSITY Certificate of Completion Awarded to Bezaleel Paul for Machine Learning & AI"
    sim = duplicate_detector.compute_text_similarity(text_orig, text_mod)
    assert sim > 0.80


@pytest.mark.asyncio
async def test_attack_07_file_changed_after_verification(student_auth_headers):
    """Attack 7 — File changed after verification -> CRITICAL FILE_CHANGED_AFTER_VERIFICATION."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with open(FIXTURES_DIR / "valid_certificate.pdf", "rb") as f:
            upload_resp = await client.post("/api/submissions", files={"file": ("tamper_test.pdf", f, "application/pdf")}, headers=student_auth_headers)
        sub_id = upload_resp.json()["id"]
        data = (await client.get(f"/api/submissions/{sub_id}", headers=student_auth_headers)).json()
        
        # Tamper with the stored file directly on disk
        stored_path = storage_provider.get_file_path(f"submissions/{data['stored_filename']}")
        with open(stored_path, "wb") as f:
            f.write(b"%PDF-1.4 TAMPERED CONTENT AFTER UPLOAD")

        # Reprocess
        p_resp = await client.post(f"/api/submissions/{sub_id}/process", headers=student_auth_headers)
        p_data = p_resp.json()
        anomalies = [a["type"] for a in p_data["anomalies"]]
        assert "A013" in anomalies  # File Changed After Verification
        assert p_data["status"] == "REVIEW"


@pytest.mark.asyncio
async def test_attack_08_student_attempts_to_set_status(student_auth_headers):
    """Attack 8 — Student attempts to set status -> 403 or validation failure."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Student cannot call review endpoint
        resp = await client.post(
            "/api/submissions/dummy-id/review",
            json={"decision": "APPROVE"},
            headers=student_auth_headers
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_attack_09_student_requests_another_student_certificate(student_auth_headers, other_student_auth_headers):
    """Attack 9 — Student requests another student's certificate -> 403."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Other student uploads a certificate
        with open(FIXTURES_DIR / "valid_certificate.pdf", "rb") as f:
            upload_resp = await client.post(
                "/api/submissions",
                files={"file": ("priv.pdf", f, "application/pdf")},
                headers=other_student_auth_headers
            )
        other_sub_id = upload_resp.json()["id"]

        # Student 1 attempts to access student 2's certificate details
        resp = await client.get(f"/api/submissions/{other_sub_id}", headers=student_auth_headers)
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_attack_10_fake_issuer_domain():
    """Attack 10 — Fake issuer domain -> UNTRUSTED."""
    from app.extraction.qr import qr_extractor
    is_trusted = qr_extractor.validate_domain("phishing-example.edu", "example.edu")
    assert is_trusted is False


@pytest.mark.asyncio
async def test_attack_11_malformed_pdf(student_auth_headers):
    """Attack 11 — Malformed PDF -> QUARANTINED / Rejected without crashing worker."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with open(FIXTURES_DIR / "malformed_pdf.pdf", "rb") as f:
            resp = await client.post(
                "/api/submissions",
                files={"file": ("malformed.pdf", f, "application/pdf")},
                headers=student_auth_headers
            )
        # Should cleanly reject with 400 Bad Request, not crash server (500)
        assert resp.status_code == 400
        assert "MALFORMED_PDF" in resp.text


@pytest.mark.asyncio
async def test_attack_12_oversized_file(student_auth_headers):
    """Attack 12 — Oversized file -> REJECTED (400)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with open(FIXTURES_DIR / "large_file_test.pdf", "rb") as f:
            resp = await client.post(
                "/api/submissions",
                files={"file": ("large.pdf", f, "application/pdf")},
                headers=student_auth_headers
            )
        assert resp.status_code == 400
        assert "FILE_TOO_LARGE" in resp.text


@pytest.mark.asyncio
async def test_attack_13_issuer_website_unavailable():
    """Attack 13 — Issuer website unavailable -> UNVERIFIABLE, not VERIFIED."""
    from app.verification.rule_engine import verification_rule_engine
    result = verification_rule_engine.evaluate(
        issuer_verification_status="UNAVAILABLE",
        identity_match_level="EXACT",
        anomalies=[],
        file_integrity_pass=True,
        duplicate_detected=False,
        qr_verification_status="PASS"
    )
    assert result.final_status == SubmissionStatus.UNVERIFIABLE


@pytest.mark.asyncio
async def test_attack_14_playwright_selector_failure():
    """Attack 14 — Playwright selector failure -> UNAVAILABLE, not VERIFIED."""
    adapter = PlaywrightIssuerAdapter()
    result = await adapter.verify(
        certificate_id="CERT-TEST",
        verification_url="http://invalid-non-existent-domain-404.com/verify"
    )
    assert result.verification_status == IssuerVerificationStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_attack_15_issuer_returns_different_recipient():
    """Attack 15 — Issuer returns different recipient -> RECIPIENT_MISMATCH."""
    from app.verification.identity import identity_matcher, IdentityMatchLevel
    res = identity_matcher.compare("Bezaleel Paul", "Different Person")
    assert res.match_level == IdentityMatchLevel.MISMATCH


@pytest.mark.asyncio
async def test_attack_16_client_submits_fake_verification_result(student_auth_headers):
    """Attack 16 — Client submits fake verification result -> backend ignores client result."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Student cannot send status in POST /api/submissions
        with open(FIXTURES_DIR / "invalid_id_certificate.pdf", "rb") as f:
            upload_resp = await client.post(
                "/api/submissions",
                files={"file": ("fake_claim.pdf", f, "application/pdf")},
                data={"status": "VERIFIED"},  # Malicious attempt to claim VERIFIED
                headers=student_auth_headers
            )
        sub_id = upload_resp.json()["id"]
        # Status MUST be PROCESSING, not VERIFIED
        assert upload_resp.json()["status"] == "PROCESSING"

        # After processing, invalid ID (CERT-1003) must be FAILED, never VERIFIED
        p_resp = await client.post(f"/api/submissions/{sub_id}/process", headers=student_auth_headers)
        assert p_resp.json()["status"] == "FAILED"
