import unicodedata
import re
from enum import Enum
from typing import Tuple, Dict, Any
from pydantic import BaseModel


class IdentityMatchLevel(str, Enum):
    EXACT = "EXACT"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    REVIEW = "REVIEW"
    MISMATCH = "MISMATCH"


class IdentityMatchResult(BaseModel):
    match_level: IdentityMatchLevel
    similarity_score: float
    student_name: str
    recipient_name: str
    normalized_student: str
    normalized_recipient: str
    reason: str


class IdentityMatcher:
    """
    Deterministic identity matching engine for recipient verification.
    Applies Unicode normalization (NFKD), punctuation cleanup, and strict token alignment.
    """

    @staticmethod
    def normalize_name(name: str) -> str:
        if not name:
            return ""
        # 1. Unicode decomposition
        nfkd = unicodedata.normalize("NFKD", name)
        # 2. Strip non-ASCII diacritics
        ascii_text = nfkd.encode("ASCII", "ignore").decode("utf-8")
        # 3. Lowercase
        lowered = ascii_text.lower()
        # 4. Remove punctuation except spacing
        cleaned = re.sub(r"[^a-z0-9\s]", "", lowered)
        # 5. Collapse whitespace
        normalized = " ".join(cleaned.split())
        return normalized

    def compare(self, student_name: str, recipient_name: str) -> IdentityMatchResult:
        norm_student = self.normalize_name(student_name)
        norm_recipient = self.normalize_name(recipient_name)

        if not norm_student or not norm_recipient:
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.MISMATCH,
                similarity_score=0.0,
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason="One or both names are missing"
            )

        # 1. Exact match after normalization
        if norm_student == norm_recipient:
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.EXACT,
                similarity_score=1.0,
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason="Exact match after normalization"
            )

        student_tokens = norm_student.split()
        recipient_tokens = norm_recipient.split()

        student_set = set(student_tokens)
        recipient_set = set(recipient_tokens)

        # 2. Token set equality (e.g. "Paul Bezaleel" vs "Bezaleel Paul")
        if student_set == recipient_set and len(student_set) > 1:
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.HIGH_CONFIDENCE,
                similarity_score=0.95,
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason="Tokens match completely in rearranged order"
            )

        # 3. Subset match (e.g. middle name present in one: "Bezaleel K. Paul" vs "Bezaleel Paul")
        intersection = student_set.intersection(recipient_set)
        if len(intersection) >= 2 and (student_set.issubset(recipient_set) or recipient_set.issubset(student_set)):
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.HIGH_CONFIDENCE,
                similarity_score=0.90,
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason="Significant token overlap with middle name or initial variation"
            )

        # Jaccard token similarity
        union = student_set.union(recipient_set)
        jaccard = len(intersection) / len(union) if union else 0.0

        if jaccard >= 0.5 and len(intersection) >= 1:
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.REVIEW,
                similarity_score=round(jaccard, 2),
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason="Partial token overlap; requires human review"
            )

        return IdentityMatchResult(
            match_level=IdentityMatchLevel.MISMATCH,
            similarity_score=round(jaccard, 2),
            student_name=student_name,
            recipient_name=recipient_name,
            normalized_student=norm_student,
            normalized_recipient=norm_recipient,
            reason="Names differ significantly"
        )


identity_matcher = IdentityMatcher()
