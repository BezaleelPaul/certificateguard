import pytest
from httpx import AsyncClient, ASGITransport
from pathlib import Path
from app.main import app
from app.models import SubmissionStatus

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "test-fixtures"


@pytest.mark.asyncio
async def test_full_submission_verification_flow(student_auth_headers, teacher_auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Student uploads valid certificate
        pdf_path = FIXTURES_DIR / "valid_certificate.pdf"
        assert pdf_path.exists(), "valid_certificate.pdf fixture must exist"

        with open(pdf_path, "rb") as f:
            files = {"file": ("valid_certificate.pdf", f, "application/pdf")}
            upload_resp = await client.post(
                "/api/submissions",
                files=files,
                headers=student_auth_headers
            )

        assert upload_resp.status_code == 200, upload_resp.text
        data = upload_resp.json()
        submission_id = data["id"]
        assert data["status"] == "PROCESSING"

        # 2. Trigger pipeline processing
        process_resp = await client.post(
            f"/api/submissions/{submission_id}/process",
            headers=student_auth_headers
        )
        assert process_resp.status_code == 200
        processed_data = process_resp.json()

        # Should be VERIFIED because recipient is Bezaleel Paul and ID is CERT-1002
        assert processed_data["status"] == "VERIFIED"
        assert processed_data["extracted_data"]["certificate_id"] == "CERT-1002"

        # 3. Retrieve Evidence Report
        evidence_resp = await client.get(
            f"/api/submissions/{submission_id}/evidence",
            headers=student_auth_headers
        )
        assert evidence_resp.status_code == 200
        report_text = evidence_resp.text
        assert "CERTIFICATE VERIFICATION REPORT" in report_text
        assert "VERIFIED" in report_text

        # 4. Teacher reviews submission
        review_payload = {
            "decision": "APPROVE",
            "notes": "Verified against university registrar system."
        }
        review_resp = await client.post(
            f"/api/submissions/{submission_id}/review",
            json=review_payload,
            headers=teacher_auth_headers
        )
        assert review_resp.status_code == 200
        review_data = review_resp.json()
        assert review_data["decision"] == "APPROVE"

        # 5. Teacher inspects Audit Logs
        audit_resp = await client.get(
            "/api/audit-logs",
            headers=teacher_auth_headers
        )
        assert audit_resp.status_code == 200
        logs = audit_resp.json()
        assert any(l["entity_id"] == submission_id for l in logs)
