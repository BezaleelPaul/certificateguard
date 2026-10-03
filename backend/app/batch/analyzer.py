"""
Row-level verification for batch analysis workbooks.

Each workbook row is analysed with the same deterministic trust machinery as
a single-certificate submission: issuer registry matching, authoritative
issuer adapter lookup, identity matching, duplicate detection, the 20-rule
anomaly engine and the final-status rule engine. Document-only signals
(OCR, QR pixels, forensics, file hash) are unavailable for spreadsheet rows
and are therefore not fabricated - the evidence simply is not there.

Verdict contract written back into the workbook:
    VERIFIED       -> LEGIT
    FAILED         -> FAKE      (only authoritative issuer records produce this)
    REVIEW         -> ANOMALY
    UNVERIFIABLE   -> ANOMALY
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.anomaly.engine import anomaly_engine
from app.anomaly.rules import VerificationContext
from app.batch.template import (
    RowVerdict,
    SheetRow,
    VERDICT_ANOMALY,
    VERDICT_FAKE,
    VERDICT_LEGIT,
)
from app.extraction.qr import qr_extractor
from app.models import ExtractedCertificateData, Issuer, Submission
from app.security.ssrf import validate_url_ssrf
from app.verification.identity import identity_matcher
from app.verification.mock_adapter import mock_issuer_adapter
from app.verification.playwright_adapter import playwright_issuer_adapter
from app.verification.rule_engine import verification_rule_engine
from app.verification.web_fetch_adapter import web_fetch_issuer_adapter

logger = logging.getLogger(__name__)

# Demo issuers resolve through the authoritative mock registry. Real issuers
# must NEVER fall through to it: the registry does not know their certificate
# IDs and would report every genuine certificate as invalid.
MOCK_REGISTRY_DOMAINS = frozenset({"example.edu", "coursera.org", "edx.org"})

STATUS_TO_VERDICT = {
    "VERIFIED": VERDICT_LEGIT,
    "FAILED": VERDICT_FAKE,
    "REVIEW": VERDICT_ANOMALY,
    "UNVERIFIABLE": VERDICT_ANOMALY,
    "ERROR": VERDICT_ANOMALY,
}


def _parse_certificate_url(url: str) -> Tuple[Optional[str], bool, Optional[str]]:
    """
    Returns (hostname, is_ssrf_safe, ssrf_reason).

    DNS resolution failure means the destination is unreachable, not
    malicious, so it is reported as safe-unreachable: the issuer adapter
    will surface it as UNAVAILABLE instead of a forged SSRF verdict.
    """
    url = (url or "").strip()
    if not url:
        return None, True, None

    try:
        parsed = urlparse(url)
    except Exception:
        return None, False, "URL could not be parsed"

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None, False, "Only http(s) verification links are permitted"

    hostname = (parsed.hostname or "").lower() or None
    ssrf = validate_url_ssrf(url)
    if not ssrf.is_safe and not ssrf.is_dns_failure:
        return hostname, False, ssrf.reason
    return hostname, True, None


def _match_issuer(
    issuers: List[Issuer], issuer_cell: str, hostname: Optional[str]
) -> Optional[Issuer]:
    if hostname:
        for issuer in issuers:
            if qr_extractor.validate_domain(hostname, issuer.official_domain):
                return issuer

    cell = (issuer_cell or "").strip()
    if cell:
        for issuer in issuers:
            if (
                issuer.name.lower() in cell.lower()
                or cell.lower() in issuer.name.lower()
            ):
                return issuer
    return None


def _issuer_config(issuer: Issuer) -> Dict[str, Any]:
    try:
        cfg = json.loads(issuer.configuration_json or "{}")
        return cfg if isinstance(cfg, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _uses_mock_registry(issuer: Issuer, config: Dict[str, Any]) -> bool:
    """Demo issuers resolve through the mock registry; real issuers never do."""
    if "use_mock_registry" in config:
        return bool(config["use_mock_registry"])
    return issuer.official_domain in MOCK_REGISTRY_DOMAINS


async def _resolve_issuer_record(
    matched_issuer: Optional[Issuer],
    certificate_id: str,
    certificate_url: str,
) -> Dict[str, Any]:
    """Safe entry point: a failing issuer check must never crash the batch.

    Any unexpected adapter error degrades to UNAVAILABLE, which the rules
    map to an honest ANOMALY with the failure surfaced in the analysis text.
    """
    try:
        return await _resolve_issuer_record_impl(
            matched_issuer, certificate_id, certificate_url
        )
    except Exception as exc:
        logger.exception("Issuer verification crashed for id %r", certificate_id)
        return {
            "status": "UNAVAILABLE",
            "certificate_id": None,
            "recipient": None,
            "course": None,
            "evidence": None,
            "method": "NONE",
            "note": f"Verification step failed: {type(exc).__name__}: {exc}",
        }


async def _resolve_issuer_record_impl(
    matched_issuer: Optional[Issuer],
    certificate_id: str,
    certificate_url: str,
) -> Dict[str, Any]:
    """Queries the authoritative issuer through the same adapter chain as the pipeline."""
    result: Dict[str, Any] = {
        "status": "UNAVAILABLE",
        "certificate_id": None,
        "recipient": None,
        "course": None,
        "evidence": None,
        "method": "NONE",
        "note": None,
    }
    if not matched_issuer:
        return result

    result["method"] = matched_issuer.verification_type
    url = (certificate_url or "").strip() or None
    config = _issuer_config(matched_issuer)

    if matched_issuer.verification_type == "WEB" and not _uses_mock_registry(
        matched_issuer, config
    ):
        # Real issuer: consult its public verification page over HTTP even
        # when the sheet's certificate ID cell is empty - the URL alone
        # identifies the credential and the recipient is read from the page.
        web_res = await web_fetch_issuer_adapter.verify(
            certificate_id=certificate_id,
            verification_url=url,
            metadata=config,
        )
        return {
            "status": web_res.verification_status.value,
            "certificate_id": web_res.certificate_id_returned,
            "recipient": web_res.recipient_returned,
            "course": web_res.course_returned,
            "evidence": web_res.raw_evidence,
            "method": "WEB",
            "note": web_res.error_message,
        }

    if not certificate_id:
        # Mock/API/MANUAL registries are keyed by certificate ID.
        return result

    if matched_issuer.verification_type == "WEB":
        target_url = url
        if not target_url and matched_issuer.verification_url:
            target_url = f"{matched_issuer.verification_url}?id={certificate_id}"
        playwright_res = await playwright_issuer_adapter.verify(
            certificate_id=certificate_id,
            verification_url=target_url,
            metadata=config,
        )
        if playwright_res.verification_status.value != "UNAVAILABLE":
            return {
                "status": playwright_res.verification_status.value,
                "certificate_id": playwright_res.certificate_id_returned,
                "recipient": playwright_res.recipient_returned,
                "course": playwright_res.course_returned,
                "evidence": playwright_res.raw_evidence,
                "method": "WEB",
                "note": playwright_res.error_message,
            }
        # Playwright unavailable -> fall back to the authoritative mock resolver.

    mock_res = await mock_issuer_adapter.verify(
        certificate_id=certificate_id,
        verification_url=url,
    )
    return {
        "status": mock_res.verification_status.value,
        "certificate_id": mock_res.certificate_id_returned,
        "recipient": mock_res.recipient_returned,
        "course": mock_res.course_returned,
        "evidence": mock_res.raw_evidence,
        "method": "MOCK" if matched_issuer.verification_type != "WEB" else "WEB->MOCK",
        "note": mock_res.error_message,
    }


async def _load_known_certificate_ids(
    db: AsyncSession, certificate_ids: List[str]
) -> Dict[str, List[Tuple[str, Optional[str]]]]:
    """certificate_id -> [(submission_id, student_id)] already stored in the platform."""
    known: Dict[str, List[Tuple[str, Optional[str]]]] = {}
    if not certificate_ids:
        return known
    result = await db.execute(
        select(
            ExtractedCertificateData.certificate_id,
            ExtractedCertificateData.submission_id,
            Submission.student_id,
        )
        .join(Submission, Submission.id == ExtractedCertificateData.submission_id)
        .where(ExtractedCertificateData.certificate_id.in_(certificate_ids))
    )
    for cert_id, submission_id, student_id in result.all():
        known.setdefault(cert_id, []).append((submission_id, student_id))
    return known


async def analyze_rows(
    rows: List[SheetRow],
    db: AsyncSession,
    *,
    batch_id: str,
    uploader_student_id: Optional[str],
    uploader_name: str,
    workbook_sha256: str,
) -> List[RowVerdict]:
    """Analyses every workbook row and returns system-owned verdicts."""
    issuer_res = await db.execute(select(Issuer).where(Issuer.active == True))  # noqa: E712
    active_issuers = list(issuer_res.scalars().all())

    certificate_ids = sorted(
        {r.certificate_id.strip() for r in rows if r.certificate_id.strip()}
    )
    known_ids = await _load_known_certificate_ids(db, certificate_ids)

    seen_in_sheet: Dict[str, int] = {}
    verdicts: List[RowVerdict] = []

    for row in rows:
        cert_id = row.certificate_id.strip()
        hostname, ssrf_safe, ssrf_reason = _parse_certificate_url(row.certificate_url)

        matched_issuer = _match_issuer(active_issuers, row.issuer, hostname)

        # Duplicate evidence ------------------------------------------------
        duplicate_matches: List[Dict[str, Any]] = []
        if cert_id:
            first_row = seen_in_sheet.get(cert_id)
            if first_row is not None:
                duplicate_matches.append(
                    {
                        "match_type": "CERTIFICATE_ID",
                        "matched_submission_id": f"sheet-row-{first_row}",
                        "other_student_id": f"SHEET_ROW_{first_row}",
                        "similarity": 1.0,
                    }
                )
            else:
                seen_in_sheet[cert_id] = row.row_number

            for submission_id, student_id in known_ids.get(cert_id, []):
                duplicate_matches.append(
                    {
                        "match_type": "CERTIFICATE_ID",
                        "matched_submission_id": submission_id,
                        "other_student_id": student_id or "UNKNOWN",
                        "similarity": 1.0,
                    }
                )

        # Authoritative issuer lookup ---------------------------------------
        issuer_record = await _resolve_issuer_record(
            matched_issuer, cert_id, row.certificate_url
        )

        # Identity: the row asserts its own subject, so compare row name vs
        # issuer-returned recipient (A007 catches the contradiction).
        identity = identity_matcher.compare(
            row.recipient_name, issuer_record["recipient"] or row.recipient_name
        )

        context = VerificationContext(
            submission_id=batch_id,
            student_id=uploader_student_id or "BATCH",
            student_name=row.recipient_name or uploader_name,
            file_sha256=workbook_sha256,
            current_file_sha256=None,
            extracted_cert_id=cert_id or None,
            extracted_recipient=row.recipient_name or None,
            extracted_course=row.course or None,
            extracted_issue_date=row.issue_date or None,
            extracted_expiry_date=row.expiry_date or None,
            extracted_qr_url=(row.certificate_url.strip() or None),
            qr_hostname=hostname,
            issuer_name=matched_issuer.name if matched_issuer else (row.issuer or None),
            issuer_domain=matched_issuer.official_domain if matched_issuer else None,
            issuer_requires_qr=bool(matched_issuer and matched_issuer.verification_url),
            issuer_verification_status=issuer_record["status"],
            issuer_returned_cert_id=issuer_record["certificate_id"],
            issuer_returned_recipient=issuer_record["recipient"],
            issuer_returned_course=issuer_record["course"],
            identity_match_level=identity.match_level.value,
            duplicate_matches=duplicate_matches,
            forensic_signal=None,
            forensic_findings=[],
            synthetic_signal=None,
            qr_is_ssrf_safe=ssrf_safe,
            qr_ssrf_reason=ssrf_reason,
            digital_signature_status=None,
        )

        anomalies, max_severity = anomaly_engine.evaluate(context)

        if row.certificate_url.strip():
            if not hostname:
                qr_status = "FAIL"
            elif matched_issuer and qr_extractor.validate_domain(
                hostname, matched_issuer.official_domain
            ):
                qr_status = "PASS"
            else:
                qr_status = "FAIL"
        else:
            qr_status = "NOT_FOUND"

        evaluation = verification_rule_engine.evaluate(
            issuer_verification_status=issuer_record["status"],
            identity_match_level=identity.match_level.value,
            anomalies=anomalies,
            file_integrity_pass=True,
            duplicate_detected=bool(duplicate_matches),
            qr_verification_status=qr_status,
            digital_signature_status=None,
        )

        verdict = STATUS_TO_VERDICT.get(evaluation.final_status.value, VERDICT_ANOMALY)

        codes = ", ".join(a.rule_code for a in anomalies) or "NONE"
        details = [
            {
                "code": a.rule_code,
                "severity": a.severity.value,
                "title": a.title,
                "description": a.description,
            }
            for a in anomalies
        ]
        anomaly_summary = "; ".join(f"{a.rule_code} {a.title}" for a in anomalies)
        analysis = evaluation.reason_summary
        if anomaly_summary:
            analysis = f"{analysis} | Findings: {anomaly_summary}"
        issuer_note = issuer_record.get("note")
        if issuer_note:
            analysis = f"{analysis} | Issuer check: {issuer_note}"

        verdicts.append(
            RowVerdict(
                row_number=row.row_number,
                verdict=verdict,
                max_severity=max_severity.value if anomalies else "NONE",
                anomaly_codes=codes,
                analysis=analysis[:32000],
                confidence=round(evaluation.confidence, 2),
                anomaly_details=details,
            )
        )

    return verdicts
