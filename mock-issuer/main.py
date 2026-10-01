"""
Mock Issuer Verification Server for CertificateGuard.
Provides both JSON API and HTML web verification for Playwright testing.
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn
import os

app = FastAPI(title="Example University Mock Certificate Issuer")

# Authoritative mock database of certificates
MOCK_CERTIFICATES = {
    "CERT-1001": {
        "certificate_id": "CERT-1001",
        "recipient_name": "Rahul Kumar",
        "course_name": "Web Security Specialization",
        "issuer": "Example University",
        "issue_date": "2025-06-15",
        "status": "VALID"
    },
    "CERT-1002": {
        "certificate_id": "CERT-1002",
        "recipient_name": "Bezaleel Paul",
        "course_name": "Machine Learning Certificate",
        "issuer": "Example University",
        "issue_date": "2025-07-20",
        "status": "VALID"
    },
    "CERT-1003": {
        "certificate_id": "CERT-1003",
        "status": "INVALID",
        "reason": "Certificate revoked or does not exist"
    },
    "CERT-1004": {
        "certificate_id": "CERT-1004",
        "recipient_name": "Sarah Chen",
        "course_name": "Cloud Architecture",
        "issuer": "Example University",
        "issue_date": "2025-08-10",
        "status": "VALID"
    }
}


class VerificationResponse(BaseModel):
    certificate_id: str
    status: str
    recipient_name: Optional[str] = None
    course_name: Optional[str] = None
    issuer: Optional[str] = None
    issue_date: Optional[str] = None
    error_message: Optional[str] = None


@app.get("/")
def root():
    return {"message": "Example University Official Verification Portal", "domain": "example.edu"}


@app.get("/mock-issuer/verify", response_model=VerificationResponse)
def verify_certificate_api(cert_id: str = Query(..., description="Certificate ID to verify")):
    record = MOCK_CERTIFICATES.get(cert_id.strip())
    if not record or record.get("status") == "INVALID":
        return VerificationResponse(
            certificate_id=cert_id,
            status="INVALID",
            error_message="Certificate not found or revoked in official records"
        )
    return VerificationResponse(
        certificate_id=record["certificate_id"],
        status=record["status"],
        recipient_name=record.get("recipient_name"),
        course_name=record.get("course_name"),
        issuer=record.get("issuer"),
        issue_date=record.get("issue_date")
    )


@app.get("/verify", response_class=HTMLResponse)
def verify_certificate_html(id: str = Query(..., description="Certificate ID")):
    """HTML portal used by web verification / Playwright adapter."""
    cert_id = id.strip()
    record = MOCK_CERTIFICATES.get(cert_id)
    if not record or record.get("status") == "INVALID":
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>Certificate Verification - Example University</title></head>
        <body style="font-family: sans-serif; padding: 2rem;">
            <h1>Example University Verification Portal</h1>
            <div id="verification-card" style="border: 2px solid red; padding: 1rem; border-radius: 8px;">
                <p>Certificate ID: <span id="cert-id">{cert_id}</span></p>
                <p>Status: <span id="cert-status" style="color: red; font-weight: bold;">INVALID</span></p>
                <p id="cert-message">The certificate ID was not found in our records or has been revoked.</p>
            </div>
        </body>
        </html>
        """
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Certificate Verification - Example University</title></head>
    <body style="font-family: sans-serif; padding: 2rem;">
        <h1>Example University Verification Portal</h1>
        <div id="verification-card" style="border: 2px solid green; padding: 1rem; border-radius: 8px;">
            <p>Certificate ID: <span id="cert-id">{record['certificate_id']}</span></p>
            <p>Status: <span id="cert-status" style="color: green; font-weight: bold;">VALID</span></p>
            <p>Recipient: <span id="cert-recipient">{record['recipient_name']}</span></p>
            <p>Course: <span id="cert-course">{record['course_name']}</span></p>
            <p>Issuer: <span id="cert-issuer">{record['issuer']}</span></p>
            <p>Issue Date: <span id="cert-date">{record['issue_date']}</span></p>
        </div>
    </body>
    </html>
    """


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
