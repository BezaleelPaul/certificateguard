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
  issuer-configured existence check (public object storage):
      object present -> VALID, object missing -> INVALID
      (mirrors the issuer's own "does this code exist" verifier)
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
from app.security.validation import normalize_url_text
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


def _plausible_person_name(name: str) -> bool:
    # Real-world certificate holders in these sheets always have >= 2
    # tokens; single words like "free" from "certificate for free" are
    # false positives we must not accept.
    return len(name.split()) >= 2


# Single-token names are accepted only for the anchored og:title pattern,
# where the surrounding phrase is rigid ("NAME has successfully completed").
_NAME_STOPWORDS = frozenset(
    {
        "free",
        "test",
        "demo",
        "course",
        "certificate",
        "example",
        "user",
        "student",
        "sample",
    }
)


def _plausible_completed_name(name: str) -> bool:
    tokens = name.split()
    if len(tokens) >= 2:
        return True
    if not tokens:
        return False
    token = tokens[0]
    return len(token) >= 3 and token.isalpha() and token.lower() not in _NAME_STOPWORDS


# Recipient phrases ordered from most to least specific. Each pattern pairs
# with the guard that decides whether its capture looks like a person name.
_RECIPIENT_PATTERNS = [
    (
        re.compile(r"verifies that ([^|<]{3,80}?) has successfully completed", re.I),
        _plausible_person_name,
    ),
    # og:title style: "NAME has successfully completed the online course ..."
    # (anchored, so a single-token name at the start is acceptable; identity
    # comparison still guards the final verdict).
    (
        re.compile(r"^(.{2,80}?)\s+has successfully completed", re.I),
        _plausible_completed_name,
    ),
    (
        re.compile(r"certificate for ([^|<]{3,80}?)(?:\.|$)", re.I),
        _plausible_person_name,
    ),
    (re.compile(r"awarded to ([^|<]{3,80}?)(?:\.|$)", re.I), _plausible_person_name),
    (re.compile(r"presented to ([^|<]{3,80}?)(?:\.|$)", re.I), _plausible_person_name),
    (
        re.compile(r"congratulations[,]? ([^|<]{3,80}?)(?:\.|!|$)", re.I),
        _plausible_person_name,
    ),
]

_COURSE_PATTERNS = [
    re.compile(
        r"completed (?:the )?(?:online |free )?course ([^|<.;]{3,90}?)(?:\.|$)", re.I
    ),
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


def _visible_text(body: str) -> str:
    stripped = re.sub(
        r"<(script|style|noscript)[^>]*>.*?</\1>", " ", body, flags=re.I | re.S
    )
    stripped = re.sub(r"<[^>]+>", " ", stripped)
    return _collapse(stripped)[:8000]


def _extract_recipient(text: str) -> Optional[str]:
    for pattern, guard in _RECIPIENT_PATTERNS:
        match = pattern.search(text)
        if match:
            candidate = _collapse(match.group(1))
            if guard(candidate):
                return candidate
    return None


def _og_meta(body: str, prop: str) -> str:
    """Reads an Open Graph meta tag (property/content in either order)."""
    pattern = re.compile(
        r"<meta[^>]*(?:property=[\"']og:"
        + prop
        + r"[\"'][^>]*content=[\"']([^\"']+)[\"']"
        + r"|content=[\"']([^\"']+)[\"'][^>]*property=[\"']og:"
        + prop
        + r"[\"'])",
        re.I,
    )
    match = pattern.search(body)
    if not match:
        return ""
    return _collapse(match.group(1) or match.group(2))


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

    async def _verify_existence(
        self,
        certificate_id: str,
        url: str,
        cfg: Dict[str, Any],
        allow_local: bool,
    ) -> AdapterVerificationResult:
        """Issuer-configured existence check against public object storage.

        Some issuers publish certificates as static objects and expose no
        HTML verification page: their own site validates a code simply by
        checking whether the object exists. A missing object is then the
        issuer's explicit "certificate not found" answer.
        """
        segment = urlparse(url).path.rstrip("/").split("/")[-1]
        prefix = str(cfg.get("strip_prefix") or "")
        code = (
            segment[len(prefix) :] if prefix and segment.startswith(prefix) else segment
        )
        if not code:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                verification_url=url,
                error_message="Existence check configured but URL carries no certificate code",
            )
        try:
            check_url = str(cfg["url_template"]).format(code=code)
        except (KeyError, IndexError, ValueError):
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                verification_url=url,
                error_message="Issuer existence check template is misconfigured",
            )

        ssrf_check = validate_url_ssrf(check_url, allow_localhost=allow_local)
        if not ssrf_check.is_safe:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                verification_url=url,
                error_message=f"Issuer existence check blocked by SSRF guard: {ssrf_check.reason}",
            )

        try:
            response = await self._afetch(check_url)
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError) as exc:
            logger.info("Existence check fetch failed for %s: %s", check_url, exc)
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                verification_url=url,
                error_message=f"Issuer existence check unreachable ({type(exc).__name__})",
            )

        status_code = response.status_code
        evidence = json.dumps(
            {"check_url": check_url, "http_status": status_code, "code": code}
        )
        if status_code == 200:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.VALID,
                certificate_id_returned=certificate_id or None,
                status_returned="VALID",
                verification_url=check_url,
                raw_evidence=evidence,
                error_message=(
                    "Issuer storage confirms this certificate exists "
                    "(recipient name not machine-readable from the image)"
                ),
            )
        if status_code in (404, 410):
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.INVALID,
                certificate_id_returned=certificate_id or None,
                status_returned=f"HTTP {status_code}",
                verification_url=check_url,
                raw_evidence=evidence,
                error_message="Issuer reports certificate not found (existence check)",
            )
        if status_code in (401, 403, 429) or status_code >= 500:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                status_returned=f"HTTP {status_code}",
                verification_url=check_url,
                raw_evidence=evidence,
                error_message=(
                    f"Issuer existence check returned HTTP {status_code} "
                    "(access restricted or outage)"
                ),
            )
        return AdapterVerificationResult(
            verification_status=IssuerVerificationStatus.UNAVAILABLE,
            certificate_id_returned=certificate_id or None,
            status_returned=f"HTTP {status_code}",
            verification_url=check_url,
            raw_evidence=evidence,
            error_message=f"Unexpected HTTP status {status_code} from issuer existence check",
        )

    async def verify(
        self,
        certificate_id: str,
        verification_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AdapterVerificationResult:
        # Repair control characters (embedded newlines from spreadsheet cells)
        # before any client sees the URL: urlsplit silently strips them, but
        # httpx rejects the raw string and would crash the whole analysis.
        url = normalize_url_text(verification_url)
        if not url:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                error_message="Row has no public certificate URL to verify against",
            )
        if not url.lower().startswith(("http://", "https://")):
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                error_message="Row certificate URL is not a fetchable http(s) link",
            )

        config = metadata or {}
        allow_local = config.get("allow_localhost", False)
        ssrf_check = validate_url_ssrf(url, allow_localhost=allow_local)
        if not ssrf_check.is_safe:
            if ssrf_check.is_dns_failure:
                return AdapterVerificationResult(
                    verification_status=IssuerVerificationStatus.UNAVAILABLE,
                    certificate_id_returned=certificate_id or None,
                    verification_url=url,
                    error_message=f"Issuer website unresolvable: {ssrf_check.reason}",
                )
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.INVALID,
                certificate_id_returned=certificate_id or None,
                verification_url=url,
                error_message=f"SSRF violation: {ssrf_check.reason}",
            )

        # Issuer-configured existence check: certificates published as static
        # objects are validated the same way the issuer's own site does it.
        existence_cfg = config.get("existence_check")
        if isinstance(existence_cfg, dict) and existence_cfg.get("url_template"):
            return await self._verify_existence(
                certificate_id, url, existence_cfg, allow_local
            )

        try:
            response = await self._afetch(url)
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError) as exc:
            logger.info("Web verification fetch failed for %s: %s", url, exc)
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                certificate_id_returned=certificate_id or None,
                verification_url=url,
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
        payload = _payload_from_url(final_url) or _payload_from_url(url)
        recipient = _payload_recipient(payload) if payload else None
        source = "redirect-token-payload" if recipient else None

        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title_text = _collapse(title_match.group(1)) if title_match else ""
        desc_match = re.search(
            r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']',
            body,
            re.I,
        )
        desc_text = _collapse(desc_match.group(1)) if desc_match else ""
        og_title = _og_meta(body, "title")
        og_desc = _og_meta(body, "description")

        # 2. Page metadata: JSON-LD, Open Graph, meta description, <title>.
        if not recipient:
            for candidate in _jsonld_candidates(body):
                recipient = candidate
                source = "json-ld"
                break

        if not recipient:
            for source_text, source_name in (
                (og_title, "og:title"),
                (og_desc, "og:description"),
                (desc_text, "meta-description"),
                (title_text, "title"),
            ):
                recipient = _extract_recipient(source_text)
                if recipient:
                    source = source_name
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
                for text in (og_title, og_desc, title_text, body[:4000]):
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
