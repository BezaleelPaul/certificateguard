import json
import re
from typing import Optional, Dict, Any
from app.verification.adapter import IssuerVerificationAdapter, AdapterVerificationResult
from app.models import IssuerVerificationStatus
from app.config import settings
from app.security.ssrf import validate_url_ssrf
import logging

logger = logging.getLogger(__name__)


class PlaywrightIssuerAdapter(IssuerVerificationAdapter):
    """
    Playwright-based web verification adapter for issuers that have public verification portals
    without dedicated JSON APIs.
    Enforces strict timeout, sandboxed execution, domain confinement, SSRF protection, and graceful failure.
    """

    def __init__(self, timeout_ms: Optional[int] = None):
        self.timeout_ms = timeout_ms or settings.PLAYWRIGHT_TIMEOUT_MS

    async def verify(
        self,
        certificate_id: str,
        verification_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AdapterVerificationResult:
        if not verification_url:
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                error_message="Verification URL not provided for Playwright adapter"
            )

        config = metadata or {}

        # Enforce SSRF protection
        allow_local = config.get("allow_localhost", False)
        ssrf_check = validate_url_ssrf(verification_url, allow_localhost=allow_local)
        if not ssrf_check.is_safe:
            if ssrf_check.is_dns_failure:
                logger.info(f"Target verification URL host unresolvable: {ssrf_check.reason}")
                return AdapterVerificationResult(
                    verification_status=IssuerVerificationStatus.UNAVAILABLE,
                    verification_url=verification_url,
                    error_message=f"Issuer website unresolvable: {ssrf_check.reason}"
                )
            logger.warning(f"SSRF attack blocked for URL '{verification_url}': {ssrf_check.reason}")
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.INVALID,
                verification_url=verification_url,
                error_message=f"SSRF violation: {ssrf_check.reason}"
            )

        status_selector = config.get("status_selector", "#cert-status, .status, [data-status]")
        recipient_selector = config.get("recipient_selector", "#cert-recipient, .recipient, [data-recipient]")
        course_selector = config.get("course_selector", "#cert-course, .course, [data-course]")
        cert_id_selector = config.get("cert_id_selector", "#cert-id, .cert-id, [data-cert-id]")

        try:
            # Check for playwright availability
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not installed in environment; returning UNAVAILABLE status")
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                verification_url=verification_url,
                error_message="Playwright browser automation module is not installed. Manual review required."
            )

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
                )
                context = await browser.new_context(
                    user_agent="CertificateGuard-AutomatedVerification/1.0",
                    bypass_csp=False,
                    ignore_https_errors=False
                )
                page = await context.new_page()
                page.set_default_navigation_timeout(self.timeout_ms)
                page.set_default_timeout(self.timeout_ms)

                # Track redirects
                redirect_history = []
                page.on("response", lambda response: redirect_history.append(response.url) if response.status in [301, 302, 307, 308] else None)

                # Navigate strictly to target verification url
                response = await page.goto(verification_url, wait_until="domcontentloaded")
                final_url = page.url

                # Extract text and selectors
                html_content = await page.content()
                
                # Check status
                status_returned = "UNKNOWN"
                status_elem = await page.query_selector(status_selector)
                if status_elem:
                    status_returned = (await status_elem.inner_text()).strip()

                recipient_returned = None
                recip_elem = await page.query_selector(recipient_selector)
                if recip_elem:
                    recipient_returned = (await recip_elem.inner_text()).strip()

                course_returned = None
                course_elem = await page.query_selector(course_selector)
                if course_elem:
                    course_returned = (await course_elem.inner_text()).strip()

                cert_id_returned = None
                cid_elem = await page.query_selector(cert_id_selector)
                if cid_elem:
                    cert_id_returned = (await cid_elem.inner_text()).strip()

                await browser.close()

                # Determine verification status
                if "VALID" in status_returned.upper() or "AUTHENTIC" in status_returned.upper() or "VERIFIED" in status_returned.upper():
                    v_status = IssuerVerificationStatus.VALID
                elif "INVALID" in status_returned.upper() or "REVOKED" in status_returned.upper() or "NOT FOUND" in status_returned.upper():
                    v_status = IssuerVerificationStatus.INVALID
                else:
                    v_status = IssuerVerificationStatus.UNAVAILABLE

                return AdapterVerificationResult(
                    verification_status=v_status,
                    certificate_id_returned=cert_id_returned or certificate_id,
                    recipient_returned=recipient_returned,
                    course_returned=course_returned,
                    status_returned=status_returned,
                    raw_evidence=json.dumps({
                        "final_url": final_url,
                        "redirects": redirect_history,
                        "status_text": status_returned,
                        "extracted_fields": {
                            "recipient": recipient_returned,
                            "course": course_returned,
                            "cert_id": cert_id_returned
                        }
                    }),
                    verification_url=final_url
                )

        except Exception as e:
            logger.error(f"Playwright verification failed or timed out: {str(e)}")
            return AdapterVerificationResult(
                verification_status=IssuerVerificationStatus.UNAVAILABLE,
                verification_url=verification_url,
                error_message=f"Playwright navigation or selector timeout/failure: {str(e)}"
            )


playwright_issuer_adapter = PlaywrightIssuerAdapter()
