"""
Synthetic Test Fixture Generator for CertificateGuard.
Generates fictional test certificates for unit, integration, and red-team testing.
"""

import os
from pathlib import Path
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors


def create_certificate_pdf(
    filepath: Path,
    cert_id: str,
    recipient: str,
    course: str,
    issuer: str = "Example University",
    issue_date: str = "2025-07-20",
    qr_url: str = None
):
    c = canvas.Canvas(str(filepath), pagesize=landscape(letter))
    width, height = landscape(letter)

    # Outer decorative border
    c.setStrokeColor(colors.HexColor("#1e3a8a"))
    c.setLineWidth(4)
    c.rect(30, 30, width - 60, height - 60)

    c.setStrokeColor(colors.HexColor("#d97706"))
    c.setLineWidth(1.5)
    c.rect(38, 38, width - 76, height - 76)

    # Header / Issuer
    c.setFont("Helvetica-Bold", 26)
    c.setFillColor(colors.HexColor("#1e3a8a"))
    c.drawCentredString(width / 2.0, height - 90, issuer.upper())

    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(colors.HexColor("#4b5563"))
    c.drawCentredString(width / 2.0, height - 120, "OFFICIAL CERTIFICATE OF COMPLETION")

    # Body
    c.setFont("Helvetica", 14)
    c.setFillColor(colors.black)
    c.drawCentredString(width / 2.0, height - 170, "This is to certify that")

    # Recipient
    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(colors.HexColor("#0f172a"))
    c.drawCentredString(width / 2.0, height - 210, recipient)

    # Details
    c.setFont("Helvetica", 14)
    c.setFillColor(colors.black)
    c.drawCentredString(width / 2.0, height - 250, "has successfully completed the course")

    # Course
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(colors.HexColor("#1d4ed8"))
    c.drawCentredString(width / 2.0, height - 290, course)

    # Issue Date and Certificate ID
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor("#334155"))
    c.drawString(70, 90, f"Issue Date: {issue_date}")
    c.drawString(70, 70, f"Certificate ID: {cert_id}")

    # Verification URL / QR placeholder
    if qr_url:
        c.drawString(width - 340, 90, "Verify Credential Online:")
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColor(colors.HexColor("#1d4ed8"))
        c.drawString(width - 340, 70, qr_url)
        # Draw mock QR box
        c.setStrokeColor(colors.black)
        c.setLineWidth(1)
        c.rect(width - 95, 55, 45, 45)
        c.setFont("Helvetica", 7)
        c.drawCentredString(width - 72.5, 75, "[QR CODE]")

    c.showPage()
    c.save()


def generate_all_fixtures():
    fixtures_dir = Path(__file__).resolve().parent
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating synthetic test fixtures in {fixtures_dir}...")

    # 1. Valid certificate (Bezaleel Paul, CERT-1002)
    create_certificate_pdf(
        filepath=fixtures_dir / "valid_certificate.pdf",
        cert_id="CERT-1002",
        recipient="Bezaleel Paul",
        course="Machine Learning Certificate",
        qr_url="https://example.edu/verify?id=CERT-1002"
    )

    # 2. Wrong recipient certificate (Rahul Kumar, CERT-1001)
    create_certificate_pdf(
        filepath=fixtures_dir / "wrong_recipient_certificate.pdf",
        cert_id="CERT-1001",
        recipient="Rahul Kumar",
        course="Web Security Specialization",
        qr_url="https://example.edu/verify?id=CERT-1001"
    )

    # 3. Invalid ID certificate (CERT-1003)
    create_certificate_pdf(
        filepath=fixtures_dir / "invalid_id_certificate.pdf",
        cert_id="CERT-1003",
        recipient="Bezaleel Paul",
        course="Machine Learning Certificate",
        qr_url="https://example.edu/verify?id=CERT-1003"
    )

    # 4. Duplicate certificate (exact byte copy of valid_certificate)
    valid_bytes = (fixtures_dir / "valid_certificate.pdf").read_bytes()
    (fixtures_dir / "duplicate_certificate.pdf").write_bytes(valid_bytes)

    # 5. Modified certificate (different visual text / modified font)
    create_certificate_pdf(
        filepath=fixtures_dir / "modified_certificate.pdf",
        cert_id="CERT-1002",
        recipient="Bezaleel Paul",
        course="Machine Learning & Deep Neural Nets",
        qr_url="https://example.edu/verify?id=CERT-1002"
    )

    # 6. Missing QR certificate
    create_certificate_pdf(
        filepath=fixtures_dir / "missing_qr_certificate.pdf",
        cert_id="CERT-1002",
        recipient="Bezaleel Paul",
        course="Machine Learning Certificate",
        qr_url=None
    )

    # 7. Untrusted QR certificate (points to malicious/untrusted domain)
    create_certificate_pdf(
        filepath=fixtures_dir / "untrusted_qr_certificate.pdf",
        cert_id="CERT-1002",
        recipient="Bezaleel Paul",
        course="Machine Learning Certificate",
        qr_url="https://evil-phishing-cert.com/verify?id=CERT-1002"
    )

    # 8. Mismatched course certificate
    create_certificate_pdf(
        filepath=fixtures_dir / "mismatched_course_certificate.pdf",
        cert_id="CERT-1002",
        recipient="Bezaleel Paul",
        course="Advanced Quantum Computing",
        qr_url="https://example.edu/verify?id=CERT-1002"
    )

    # 9. Malformed PDF (corrupted header/structure)
    malformed_path = fixtures_dir / "malformed_pdf.pdf"
    malformed_path.write_bytes(b"%PDF-1.4 CORRUPTED FILE CONTENT THAT CRASHES UNPROTECTED PARSERS \x00\xff\xfe\x01\x02\x03\x04")

    # 10. Large file test (16MB dummy file exceeding 15MB limit)
    large_file_path = fixtures_dir / "large_file_test.pdf"
    with open(large_file_path, "wb") as f:
        f.write(b"%PDF-1.4\n")
        f.write(b"0" * (16 * 1024 * 1024))  # 16MB of data

    print("All 10 test fixtures created successfully!")


if __name__ == "__main__":
    generate_all_fixtures()
