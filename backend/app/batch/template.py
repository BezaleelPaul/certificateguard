"""
Strict CertificateGuard batch-analysis workbook format.

The workbook is a two-zone contract:

- INPUT columns (A-G) are owned by the user: recipient, certificate ID,
  course, issuer, verification link, dates.
- OUTPUT/ANALYSIS columns (H-L) are owned by the system: verdict, max
  severity, anomaly codes, analysis, confidence.

Format rules enforced on every upload:
  1. The worksheet must be named "Certificates".
  2. Row 1 must be exactly the declared header list, in order.
  3. No columns outside the declared list may exist.
  4. Reserved OUTPUT columns must be empty on upload (a client can never
     smuggle its own verdict into the analysis zone).
  5. At most MAX_BATCH_ROWS data rows.

The generated template and every analysed result sheet carry Excel cell
protection: input cells are unlocked, header and output/analysis cells are
locked, and sheet protection is enabled so the zones cannot be overwritten.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, Dict, List, Optional

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill, Protection
from openpyxl.utils import get_column_letter

from app.security.validation import normalize_url_text

SHEET_NAME = "Certificates"
GUIDE_SHEET_NAME = "FORMAT_GUIDE"

INPUT_COLUMNS = [
    "RECIPIENT_NAME",
    "CERTIFICATE_ID",
    "COURSE",
    "ISSUER",
    "CERTIFICATE_URL",
    "ISSUE_DATE",
    "EXPIRY_DATE",
]

OUTPUT_COLUMNS = [
    "VERDICT",
    "MAX_SEVERITY",
    "ANOMALY_CODES",
    "ANALYSIS",
    "CONFIDENCE",
]

ALL_COLUMNS = INPUT_COLUMNS + OUTPUT_COLUMNS

MAX_BATCH_ROWS = 500

VERDICT_LEGIT = "LEGIT"
VERDICT_FAKE = "FAKE"
VERDICT_ANOMALY = "ANOMALY"
VALID_VERDICTS = (VERDICT_LEGIT, VERDICT_FAKE, VERDICT_ANOMALY)

HEADER_INPUT_FILL = PatternFill("solid", fgColor="1D4ED8")
HEADER_OUTPUT_FILL = PatternFill("solid", fgColor="6B7280")
HEADER_FONT = Font(color="FFFFFF", bold=True)

VERDICT_FILLS: Dict[str, PatternFill] = {
    VERDICT_LEGIT: PatternFill("solid", fgColor="C6EFCE"),
    VERDICT_FAKE: PatternFill("solid", fgColor="FFC7CE"),
    VERDICT_ANOMALY: PatternFill("solid", fgColor="FFEB9C"),
}

GUIDE_LINES = [
    "CERTIFICATEGUARD BATCH ANALYSIS - FORMAT CONTRACT",
    "",
    "1. The worksheet that holds data MUST be named 'Certificates'.",
    f"2. Row 1 must be exactly: {' | '.join(ALL_COLUMNS)}",
    "3. Fill only the INPUT columns (blue header). One certificate per row.",
    "4. Never type into the OUTPUT/ANALYSIS columns (grey header).",
    "   They are reserved for the platform and are rejected if pre-filled.",
    "5. CERTIFICATE_URL must be the issuer's public verification link",
    "   (https://...). Leave blank if the certificate has no link.",
    "6. Dates: use YYYY-MM-DD. Leave blank when unknown.",
    f"7. Maximum {MAX_BATCH_ROWS} data rows per workbook.",
    "8. Upload -> the platform analyses each row and writes back:",
    "   VERDICT          LEGIT | FAKE | ANOMALY",
    "   MAX_SEVERITY     NONE | LOW | MEDIUM | HIGH | CRITICAL",
    "   ANOMALY_CODES    e.g. A001, A007",
    "   ANALYSIS         human-readable evidence summary",
    "   CONFIDENCE       0.00 - 1.00",
    "9. VERDICT meanings:",
    "   LEGIT    - issuer authoritative records confirmed the certificate",
    "              and the recipient matches. Evidence-based pass.",
    "   FAKE     - issuer authoritative records declare the certificate",
    "              ID non-existent or revoked. Only the issuer can",
    "              produce this verdict.",
    "   ANOMALY  - contradictory, untrusted or missing evidence.",
    "              routed for human review.",
    "10. Output/analysis cells are locked; input cells stay editable.",
]


class WorkbookFormatError(ValueError):
    """Raised when an uploaded workbook violates the format contract."""

    def __init__(self, errors: List[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class SheetRow:
    """One analysed certificate row extracted from the workbook."""

    row_number: int
    recipient_name: str = ""
    certificate_id: str = ""
    course: str = ""
    issuer: str = ""
    certificate_url: str = ""
    issue_date: str = ""
    expiry_date: str = ""

    @property
    def has_input(self) -> bool:
        return any(
            [
                self.recipient_name,
                self.certificate_id,
                self.course,
                self.issuer,
                self.certificate_url,
                self.issue_date,
                self.expiry_date,
            ]
        )


@dataclass
class RowVerdict:
    """System-owned analysis result written back into the OUTPUT zone."""

    row_number: int
    verdict: str
    max_severity: str
    anomaly_codes: str
    analysis: str
    confidence: float
    anomaly_details: List[Dict[str, Any]] = field(default_factory=list)


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, _dt.datetime):
        return value.date().isoformat()
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def build_template_bytes() -> bytes:
    """Generates the official blank workbook with locked output/analysis zones."""
    wb = Workbook()

    ws = wb.active
    ws.title = SHEET_NAME

    for idx, header in enumerate(ALL_COLUMNS, start=1):
        cell = ws.cell(row=1, column=idx, value=header)
        cell.font = HEADER_FONT
        cell.fill = HEADER_INPUT_FILL if header in INPUT_COLUMNS else HEADER_OUTPUT_FILL
        cell.alignment = Alignment(
            horizontal="center", vertical="center", wrap_text=True
        )

    widths = [24, 20, 30, 24, 44, 14, 14, 14, 15, 24, 60, 12]
    for idx, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(idx)].width = width

    # Zone protection: header + output locked, input cells editable.
    for col_idx in range(1, len(ALL_COLUMNS) + 1):
        header_cell = ws.cell(row=1, column=col_idx)
        header_cell.protection = Protection(locked=True)

    sample_row = 2
    for col_idx in range(1, len(INPUT_COLUMNS) + 1):
        ws.cell(row=sample_row, column=col_idx).protection = Protection(locked=False)
    for col_idx in range(len(INPUT_COLUMNS) + 1, len(ALL_COLUMNS) + 1):
        ws.cell(row=sample_row, column=col_idx).protection = Protection(locked=True)

    ws.protection.sheet = True
    ws.freeze_panes = "A2"

    guide = wb.create_sheet(GUIDE_SHEET_NAME)
    for idx, line in enumerate(GUIDE_LINES, start=1):
        guide.cell(row=idx, column=1, value=line)
    guide.column_dimensions["A"].width = 100

    return _save_workbook(wb)


def parse_workbook(content: bytes) -> List[SheetRow]:
    """
    Validates the workbook against the format contract and returns data rows.
    Raises WorkbookFormatError listing every violation found.
    """
    try:
        wb = load_workbook(BytesIO(content), data_only=True)
    except Exception as exc:  # pragma: no cover - guarded by upload validation
        raise WorkbookFormatError([f"Workbook could not be opened: {exc}"])

    errors: List[str] = []

    if SHEET_NAME not in wb.sheetnames:
        raise WorkbookFormatError(
            [
                f"Missing worksheet named '{SHEET_NAME}'. Found: {', '.join(wb.sheetnames) or '(none)'}. "
                "Download the official template and keep the sheet name."
            ]
        )

    ws = wb[SHEET_NAME]

    header_values = []
    for col_idx in range(1, len(ALL_COLUMNS) + 1):
        header_values.append(_cell_text(ws.cell(row=1, column=col_idx).value))

    if header_values != ALL_COLUMNS:
        missing = [h for h in ALL_COLUMNS if h not in header_values]
        unexpected = [h for h in header_values if h and h not in ALL_COLUMNS]
        misordered = [h for h in header_values if h and h in ALL_COLUMNS]
        detail = (
            f"Header row must be exactly: {' | '.join(ALL_COLUMNS)}. "
            f"Found: {' | '.join(h for h in header_values if h) or '(empty)'}"
        )
        if missing:
            detail += f" Missing: {', '.join(missing)}."
        if unexpected:
            detail += f" Unexpected: {', '.join(unexpected)}."
        if not missing and not unexpected and misordered != ALL_COLUMNS:
            detail += " Columns are out of order."
        errors.append(detail)

    # No undeclared columns beyond the contract.
    if ws.max_column and ws.max_column > len(ALL_COLUMNS):
        extra_headers = [
            _cell_text(ws.cell(row=1, column=c).value) or f"col {get_column_letter(c)}"
            for c in range(len(ALL_COLUMNS) + 1, ws.max_column + 1)
            if _cell_text(ws.cell(row=1, column=c).value)
            or any(
                _cell_text(ws.cell(row=r, column=c).value)
                for r in range(1, min(ws.max_row, 50) + 1)
            )
        ]
        if extra_headers:
            errors.append(
                "Undeclared column(s) found outside the format contract: "
                + ", ".join(extra_headers)
            )

    output_start = len(INPUT_COLUMNS) + 1
    output_end = len(ALL_COLUMNS)
    rows: List[SheetRow] = []
    data_row_count = 0

    if ws.max_row and ws.max_row >= 2:
        for row_idx in range(2, ws.max_row + 1):
            inputs = [
                _cell_text(ws.cell(row=row_idx, column=c).value)
                for c in range(1, len(INPUT_COLUMNS) + 1)
            ]

            reserved = [
                _cell_text(ws.cell(row=row_idx, column=c).value)
                for c in range(output_start, output_end + 1)
            ]
            if any(reserved):
                filled = [OUTPUT_COLUMNS[i] for i, val in enumerate(reserved) if val]
                errors.append(
                    f"Row {row_idx}: reserved output column(s) already contain data "
                    f"({', '.join(filled)}). The analysis zone is system-owned and "
                    "must be empty on upload."
                )

            if not any(inputs):
                continue

            data_row_count += 1
            rows.append(
                SheetRow(
                    row_number=row_idx,
                    recipient_name=inputs[0],
                    certificate_id=inputs[1],
                    course=inputs[2],
                    issuer=inputs[3],
                    certificate_url=normalize_url_text(inputs[4]),
                    issue_date=inputs[5],
                    expiry_date=inputs[6],
                )
            )

    if data_row_count > MAX_BATCH_ROWS:
        errors.append(
            f"Workbook contains {data_row_count} data rows; the maximum is {MAX_BATCH_ROWS}."
        )

    if data_row_count == 0 and not errors:
        errors.append(
            "Workbook contains no data rows. Add at least one certificate row "
            "under the header row."
        )

    if errors:
        raise WorkbookFormatError(errors)

    return rows


def write_results(content: bytes, results: List[RowVerdict]) -> bytes:
    """
    Writes analysis verdicts into the reserved OUTPUT columns of the original
    workbook and re-applies zone protection. Input cells and formatting are
    preserved untouched.
    """
    try:
        wb = load_workbook(BytesIO(content))
    except Exception as exc:  # pragma: no cover - guarded by upload validation
        raise WorkbookFormatError(
            [f"Workbook could not be re-opened for writing: {exc}"]
        )

    if SHEET_NAME not in wb.sheetnames:
        raise WorkbookFormatError([f"Missing worksheet named '{SHEET_NAME}'."])

    ws = wb[SHEET_NAME]
    output_start = len(INPUT_COLUMNS) + 1

    by_row: Dict[int, RowVerdict] = {r.row_number: r for r in results}

    max_row = ws.max_row or 1
    for row_idx in range(1, max_row + 1):
        is_header = row_idx == 1
        # Input zone: editable for data rows, locked on the header row.
        for col_idx in range(1, len(INPUT_COLUMNS) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.protection = Protection(locked=is_header)

        # Output/analysis zone: always system-owned and locked.
        for offset, header in enumerate(OUTPUT_COLUMNS):
            col_idx = output_start + offset
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.protection = Protection(locked=True)
            if is_header:
                cell.value = header
                cell.font = HEADER_FONT
                cell.fill = HEADER_OUTPUT_FILL
                cell.alignment = Alignment(
                    horizontal="center", vertical="center", wrap_text=True
                )

        verdict_row = by_row.get(row_idx)
        if verdict_row is None:
            continue

        values = [
            verdict_row.verdict,
            verdict_row.max_severity,
            verdict_row.anomaly_codes,
            verdict_row.analysis,
            verdict_row.confidence,
        ]
        for offset, value in enumerate(values):
            cell = ws.cell(row=row_idx, column=output_start + offset)
            cell.value = value
            cell.protection = Protection(locked=True)
            cell.alignment = Alignment(vertical="top", wrap_text=(offset == 3))

        verdict_cell = ws.cell(row=row_idx, column=output_start)
        verdict_cell.fill = VERDICT_FILLS.get(
            verdict_row.verdict, VERDICT_FILLS[VERDICT_ANOMALY]
        )
        verdict_cell.font = Font(bold=True)
        confidence_cell = ws.cell(row=row_idx, column=output_start + 4)
        confidence_cell.number_format = "0.00"

    ws.protection.sheet = True
    ws.freeze_panes = "A2"

    return _save_workbook(wb)


def _save_workbook(wb: Workbook) -> bytes:
    buffer = BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def expected_format_description() -> str:
    return f"Worksheet '{SHEET_NAME}' with header row: {' | '.join(ALL_COLUMNS)}"
