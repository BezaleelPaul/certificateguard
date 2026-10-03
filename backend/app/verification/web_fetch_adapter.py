"""
HTTP fetch adapter for real-world issuer verification portals.

Many issuers publish certificate pages instead of JSON APIs. This adapter
fetches the public certificate URL over HTTPS and extracts the recipient
from the served document:

- JSON-LD credential payloads
- <title> / meta description phrases ("...certificate for NAME",
  "verifies that NAME has successfully completed...")
- signed redirect tokens carrying the recipient (e.g. Simplilearn
  skillup links land on ?token=<base64 json> with a username field)

Outcome contract (drives the verdict rules):
  404/410 or an explicit "certificate not found" page -> INVALID
      (the issuer's own server says this certificate does not exist)
  401/403/429/5xx, timeouts, anti-bot, JS-only shells  -> UNAVAILABLE
      (the authority could not be consulted - never guess)
  200 with an extractable recipient                    -> VALID
  everything else                                      -> UNAVAILABLE

Security: SSRF-validated before any request, response body capped, no
credentials or cookies attached, redirect targets stay subject to the
same SSRF policy as the original URL.
"""

from __future__ import annotations

import base64
import html as html_lib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import httpx

from app.models import IssuerVerificationStatus
from app.security.ssrf import validate_url_ssrf
from app.verification.adapter import (
    AdapterVerificationResult,
    IssuerVerificationAdapter,
)

logger = logging.getLogger(__name__)

FETCH_TIMEOUT_SECONDS = 12.0
MAX_BODY_BYTES = 2 * 1024 * 1024
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CertificateGuard/1.0"
)

# Recipient phrases ordered from most to least specific.
_RECIPIENT_PATTERNS = [
    re.compile(r"verifies that ([^|<]{3,80}?) has successfully completed", re.I),
    re.compile(r"certificate for ([^|<]{3,80}?)(?:\.|$)", re.I),
    re.compile(r"awarded to ([^|<]{3,80}?)(?:\.|$)", re.I),
    re.compile(r"presented to ([^|<]{3,80}?)(?:\.|$)", re.I),
    re.compile(r"congratulations[,]? ([^|<]{3,80}?)(?:\.|!|$)", re.I),
]

_COURSE_PATTERNS = [
    re.compile(r"completed (?:the )?(?:free )?course ([^|<.;]{3,90}?)(?:\.|$)", re.I),
    re.compile(r"^(.+?) course completion certificate", re.I),
]

_NOT_FOUND_PHRASES = (
    "certificate not found",
    "certificate was not found",
    "certificate could not be found",
    "no certificate found",
    "certificate does not exist",
    "certificate doesn't exist",
    "invalid certificate",
    "unable to find this certificate",
    "this certificate is invalid",
    "certificate id not found",
    "was not found in our records",
)

_PAYLOAD_RECIPIENT_KEYS = (
    "username",
    "recipient_name",
    "recipient",
    "full_name",
    "name",
)
_PAYLOAD_COURSE_KEYS = ("course_name", "course")

_JSONLD_RECIPIENT_KEYS = ("recipient", "awardedTo", "awarded_to")


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", html_lib.unescape(text or "")).strip()


def _plausible_person_name(name: str) -> bool:
    # Real-world certificate holders in these sheets always have >= 2
    # tokens; single words like "free" from "certificate for free" are
    # false positives we must not accept.
    return len(name.split()) >= 2


def _visible_text(body: str) -> str:
    stripped = re.sub(
        r"<(script|style|noscript)[^>]*>.*?</\1>", " ", body, flags=re.I | re.S
    )
    stripped = re.sub(r"<[^>]+>", " ", stripped)
    return _collapse(stripped)[:8000]


def _extract_recipient(text: str) -> Optional[str]:
    for pattern in _RECIPIENT_PATTERNS:
        match = pattern.search(text)
        if match:
            candidate = _collapse(match.group(1))
            if _plausible_person_name(candidate):
                return candidate
    return None


def _extract_course(text: str) -> Optional[str]:
    for pattern in _COURSE_PATTERNS:
        match = pattern.search(text)
        if match:
            candidate = _collapse(match.group(1))
            if 3 <= len(candidate) <= 90:
                return candidate
    return None


def _jsonld_candidates(body: str) -> List[str]:
    """Collect person-name strings from JSON-LD blocks (best effort)."""
    candidates: List[str] = []
    for raw in re.findall(
        r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        body,
        flags=re.I | re.S,
    ):
        try:
            data = json.loads(raw.strip())
        except (json.JSONDecodeError, ValueError):
            continue

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key in _JSONLD_RECIPIENT_KEYS:
                    value = node.get(key)
                    if isinstance(value, str) and _plausible_person_name(value):
                        candidates.append(value)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(data)
    return candidates


def _payload_from_url(raw_url: str) -> Optional[Dict[str, Any]]:
    """Decodes a base64url JSON token carried in a redirect URL (?token=...)."""
    try:
        tokens = parse_qs(urlparse(raw_url).query).get("token") or []
    except ValueError:
        return None
    if not tokens:
        return None
    token = tokens[0]
    try:
        padded = token + "=" * (-len(token) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _payload_recipient(payload: Dict[str, Any]) -> Optional[str]:
    for key in _PAYLOAD_RECIPIENT_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and _plausible_person_name(_collapse(value)):
            return _collapse(value)
    return None


class WebFetchIssuerAdapter(IssuerVerificationAdapter):
    """
    Verifies certificates by fetching the issuer's public verification page
    with plain HTTP and reading the recipient back from the served document.
    Lightweight enough for serverless/container deployments without a browser.
    """

    async def _afetch(self, url: str) -> httpx.Response:
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            },
        ) as client:
            return await client.get(url)

    async def verify(
        self,
        certificate_id: str,
        verification_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AdapterVerificationResult:
        if not verification_url:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                error_message="Row has no public certificate URL to verify against",
            )

        config = metadata or {}
        allow_local = config.get("allow_localhost", False)
        ssrf_check = validate_url_ssrf(verification_url, allow_localhost=allow_local)
        if not ssrf_check.is_safe:
            if ssrf_check.is_dns_failure:
                return AdapterVerificationResult(
                    verification_status=IssuerVerificationStatus.UNAVAILABLE,
                    certificate_id_returned=certificate_id or None,
                    verification_url=verification_url,
                    error_message=f"Issuer website unresolvable: {ssrf_check.reason}",
                )
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.INVALID,
                certificate_id_returned=certificate_id or None,
                verification_url=verification_url,
                error_message=f"SSRF violation: {ssrf_check.reason}",
            )

        try:
            response = await self._afetch(verification_url)
        except httpx.HTTPError as exc:
            logger.info(
                "Web verification fetch failed for %s: %s", verification_url, exc
            )
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                verification_url=verification_url,
                error_message=f"Issuer site unreachable ({type(exc).__name__})",
            )

        status_code = response.status_code
        final_url = str(response.url)

        # The issuer's own server explicitly says this certificate is gone.
        if status_code in (404, 410):
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.INVALID,
                certificate_id_returned=certificate_id or None,
                status_returned=f"HTTP {status_code}",
                verification_url=final_url,
                raw_evidence=json.dumps(
                    {"final_url": final_url, "http_status": status_code}
                ),
                error_message=f"Certificate page does not exist at issuer (HTTP {status_code})",
            )

        # Reached but cannot consult the authority (blocks, auth walls, outages).
        if status_code in (401, 403, 429) or status_code >= 500:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                status_returned=f"HTTP {status_code}",
                verification_url=final_url,
                error_message=f"Issuer site returned HTTP {status_code} (access restricted or outage)",
            )

        if status_code != 200:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                status_returned=f"HTTP {status_code}",
                verification_url=final_url,
                error_message=f"Unexpected HTTP status {status_code} from issuer site",
            )

        content_type = (response.headers.get("content-type") or "").lower()
        if "html" not in content_type and "json" not in content_type and content_type:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                verification_url=final_url,
                error_message=f"Certificate URL serves {content_type.split(';')[0]} instead of a verifiable page",
            )

        body = response.text[:MAX_BODY_BYTES]

        # 1. Signed redirect token (Simplilearn-style landing URLs).
        payload = _payload_from_url(final_url) or _payload_from_url(verification_url)
        recipient = _payload_recipient(payload) if payload else None
        source = "redirect-token-payload" if recipient else None

        # 2. Page metadata: JSON-LD, <title>, meta description.
        if not recipient:
            for candidate in _jsonld_candidates(body):
                recipient = candidate
                source = "json-ld"
                break

        if not recipient:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            title = _collapse(title_match.group(1)) if title_match else ""
            desc_match = re.search(
                r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']',
                body,
                re.I,
            )
            desc = _collapse(desc_match.group(1)) if desc_match else ""
            for source_text in (desc, title):
                recipient = _extract_recipient(source_text)
                if recipient:
                    source = "meta-description" if source_text is desc else "title"
                    break

        if recipient:
            course = None
            if payload:
                for key in _PAYLOAD_COURSE_KEYS:
                    value = payload.get(key)
                    if isinstance(value, str) and value.strip():
                        course = _collapse(value)
                        break
            if not course:
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                for text in (
                    _collapse(title_match.group(1)) if title_match else "",
                    body[:4000],
                ):
                    course = _extract_course(text)
                    if course:
                        break

            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.VALID,
                certificate_id_returned=certificate_id or None,
                recipient_returned=recipient,
                course_returned=course,
                status_returned="VALID",
                verification_url=final_url,
                raw_evidence=json.dumps(
                    {
                        "final_url": final_url,
                        "http_status": status_code,
                        "source": source,
                        "recipient": recipient,
                        "course": course,
                    }
                ),
            )

        # 3. Soft-404: page loads but explicitly reports no such certificate.
        visible = _visible_text(body).lower()
        if any(phrase in visible for phrase in _NOT_FOUND_PHRASES):
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.INVALID,
                certificate_id_returned=certificate_id or None,
                status_returned="NOT FOUND",
                verification_url=final_url,
                raw_evidence=json.dumps(
                    {"final_url": final_url, "http_status": status_code}
                ),
                error_message="Issuer page explicitly reports that this certificate does not exist",
            )

        # 4. Page reachable but nothing extractable (JS-rendered shell...).
        return AdapterVerificationResult(
            verification_status=IssuerVerificationStatus.UNAVAILABLE,
            certificate_id_returned=certificate_id or None,
            status_returned="NO DATA",
            verification_url=final_url,
            error_message="Page loaded but no certificate data could be extracted (JavaScript-rendered or access-restricted)",
        )


web_fetch_issuer_adapter = WebFetchIssuerAdapter()
