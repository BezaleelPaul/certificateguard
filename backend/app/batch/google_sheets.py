"""
Google Sheets intake for batch analysis.

Fetches a shared Google Sheet as .xlsx and adapts arbitrary tabular layouts
onto the strict CertificateGuard format contract.

Security properties:
- The spreadsheet ID is extracted from an allow-listed host and the export
  URL is constructed server-side, so the fetch target is never attacker
  controlled (no SSRF).
- The export is size-capped and must be a real xlsx (PK magic bytes).
- The adapter only ever maps source columns into INPUT columns; the
  OUTPUT/analysis zone is always generated empty, so a remote sheet can
  never smuggle pre-filled verdicts into the locked zone.
"""

from __future__ import annotations

import re
from io import BytesIO
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from openpyxl import Workbook, load_workbook

from app.batch.template import (
    ALL_COLUMNS,
    INPUT_COLUMNS,
    SHEET_NAME,
    WorkbookFormatError,
    _cell_text,
)

SHEET_ID_RE = re.compile(r"/spreadsheets/d/([A-Za-z0-9_-]{10,})")
ALLOWED_HOSTS = frozenset({"docs.google.com", "sheets.google.com"})
EXPORT_URL_TEMPLATE = (
    "https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=xlsx"
)
MAX_EXPORT_BYTES = 15 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 30.0
MAX_HEADER_SCAN_ROWS = 5
USER_AGENT = "CertificateGuard/1.0"

# Ordered keyword map: first matching contract INPUT header wins per source
# column, and each contract header can only be claimed once.
_HEADER_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "CERTIFICATE_URL": ("link", "url", "href"),
    "CERTIFICATE_ID": (
        "registration",
        "reg no",
        "reg. no",
        "reg#",
        "certificate id",
        "cert id",
    ),
    "RECIPIENT_NAME": ("name", "recipient"),
    "COURSE": ("course", "program", "subject"),
    "ISSUER": ("issuer", "institution", "organization", "authority"),
    "ISSUE_DATE": ("issue date", "issued", "date of issue"),
    "EXPIRY_DATE": ("expiry", "expiration", "valid till", "valid until"),
}


class GoogleSheetError(ValueError):
    """Raised when a Google Sheet URL cannot be accepted or downloaded."""


def extract_sheet_id(url: str) -> str:
    """Validates a Google Sheets share link and returns its spreadsheet ID."""
    raw = (url or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise GoogleSheetError("Google Sheet URL must start with https://")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise GoogleSheetError("Only docs.google.com spreadsheet links are supported.")
    match = SHEET_ID_RE.search(parsed.path or "")
    if not match:
        raise GoogleSheetError(
            "Could not find a spreadsheet ID in the URL - paste the full link "
            "from your browser address bar (it contains /spreadsheets/d/...)."
        )
    return match.group(1)


async def fetch_sheet_export(sheet_id: str) -> bytes:
    """Downloads the sheet as .xlsx via a server-constructed export URL."""
    url = EXPORT_URL_TEMPLATE.format(sheet_id=sheet_id)
    try:
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True
        ) as client:
            response = await client.get(url, headers={"User-Agent": USER_AGENT})
    except httpx.HTTPError as exc:
        raise GoogleSheetError(f"Could not reach Google Sheets: {exc}") from exc

    if response.status_code in (401, 403):
        raise GoogleSheetError(
            "Google Sheets denied access - set the sheet's sharing to "
            "'Anyone with the link can view'."
        )
    if response.status_code == 404:
        raise GoogleSheetError("Google Sheet not found - check the link.")
    if response.status_code != 200:
        raise GoogleSheetError(
            f"Google Sheets export failed (HTTP {response.status_code})."
        )

    content = response.content
    if len(content) > MAX_EXPORT_BYTES:
        raise GoogleSheetError(
            f"Spreadsheet export is larger than {MAX_EXPORT_BYTES // (1024 * 1024)}MB."
        )
    if not content.startswith(b"PK"):
        raise GoogleSheetError(
            "The link did not return an Excel workbook. Make sure the sheet is "
            "shared as 'Anyone with the link can view'."
        )
    return content


def _map_header_row(values: List[str]) -> Dict[int, str]:
    """Maps source column indexes to contract INPUT headers (best effort)."""
    mapping: Dict[int, str] = {}
    claimed: set = set()
    for idx, raw in enumerate(values):
        header = raw.lower()
        if not header:
            continue
        for target, keywords in _HEADER_KEYWORDS.items():
            if target in claimed:
                continue
            if any(keyword in header for keyword in keywords):
                mapping[idx] = target
                claimed.add(target)
                break
    return mapping


def _try_adapt_sheet(ws) -> Optional[bytes]:
    """Builds a contract workbook from one worksheet, or None if unmappable."""
    max_row = ws.max_row or 0
    scan_limit = min(max_row, MAX_HEADER_SCAN_ROWS)

    for header_row in range(1, scan_limit + 1):
        values = [
            _cell_text(ws.cell(row=header_row, column=c).value)
            for c in range(1, (ws.max_column or 0) + 1)
        ]
        mapping = _map_header_row(values)
        targets = set(mapping.values())
        if "RECIPIENT_NAME" not in targets:
            continue
        if not targets.intersection({"CERTIFICATE_URL", "CERTIFICATE_ID"}):
            continue

        out = Workbook()
        ows = out.active
        ows.title = SHEET_NAME
        ows.append(ALL_COLUMNS)

        col_for: Dict[str, int] = {
            target: col_idx + 1 for col_idx, target in mapping.items()
        }
        data_rows = 0
        for row_idx in range(header_row + 1, max_row + 1):
            inputs = [
                _cell_text(ws.cell(row=row_idx, column=col_for[name]).value)
                if name in col_for
                else ""
                for name in INPUT_COLUMNS
            ]
            if not any(inputs):
                continue
            ows.append(inputs + [""] * (len(ALL_COLUMNS) - len(INPUT_COLUMNS)))
            data_rows += 1

        if data_rows == 0:
            raise WorkbookFormatError(
                [
                    f"Found column headers (row {header_row}) but no data rows "
                    "underneath them."
                ]
            )
        if data_rows > 500:
            # parse_workbook enforces the limit too; fail early with context.
            raise WorkbookFormatError(
                [f"Spreadsheet contains {data_rows} data rows; the maximum is 500."]
            )

        buffer = BytesIO()
        out.save(buffer)
        return buffer.getvalue()

    return None


def adapt_workbook(content: bytes) -> Tuple[bytes, str]:
    """
    Returns (contract_workbook_bytes, mode) where mode is 'contract' when the
    sheet already follows the format contract, or 'mapped' when columns were
    heuristically mapped onto it. Raises WorkbookFormatError otherwise.
    """
    try:
        wb = load_workbook(BytesIO(content), data_only=True)
    except Exception as exc:
        raise WorkbookFormatError(
            [f"Downloaded spreadsheet could not be opened: {exc}"]
        )

    if SHEET_NAME in wb.sheetnames:
        ws = wb[SHEET_NAME]
        headers = [
            _cell_text(ws.cell(row=1, column=c).value)
            for c in range(1, len(ALL_COLUMNS) + 1)
        ]
        if headers == ALL_COLUMNS:
            return content, "contract"
        found = " | ".join(h for h in headers if h) or "(empty)"
        raise WorkbookFormatError(
            [
                f"Worksheet 'Certificates' exists but the header row does not "
                f"match the contract. Expected: {' | '.join(ALL_COLUMNS)}. "
                f"Found: {found}."
            ]
        )

    for ws in wb.worksheets:
        adapted = _try_adapt_sheet(ws)
        if adapted is not None:
            return adapted, "mapped"

    raise WorkbookFormatError(
        [
            "Could not find a usable header row in the spreadsheet. Expected "
            "column headers containing a recipient/student NAME plus a "
            "certificate LINK/URL or REGISTRATION/CERTIFICATE ID (for example: "
            "'NAME OF THE STUDENT | REGISTRATION NUMBER | LINKS OF CERTIFICATES'), "
            "or upload a workbook built from the official template."
        ]
    )
