import unicodedata
import re
from enum import Enum
from typing import Tuple, Dict, Any, List, Set, Optional
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


HONORIFIC_PREFIXES: Set[str] = {
    "dr", "doctor", "mr", "mrs", "ms", "miss",
    "prof", "professor", "engr", "engineer",
    "rev", "reverend", "sir", "madam", "dame",
    "shri", "smt", "kumar", "kumari"
}

HONORIFIC_SUFFIXES: Set[str] = {
    "jr", "sr", "ii", "iii", "iv", "esq",
    "phd", "md", "btech", "mtech", "bsc", "msc",
    "mba", "cpa", "pe"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class IdentityMatcher:
    """
    Deterministic identity matching engine for recipient verification.
    Applies Unicode normalization (NFKD), honorific/suffix stripping,
    inverted 'LastName, FirstName' handling, initial expansion matching,
    and Levenshtein edit distance evaluation.
    """

    @staticmethod
    def extract_cleaned_tokens(name: str) -> Tuple[str, List[str]]:
        if not name:
            return "", []

        cleaned_input = name.strip()
        # Normalize internal acronym dots: "ph.d." -> "phd", "b.tech" -> "btech"
        cleaned_input = re.sub(r"(?<=\w)\.(?=\w)", "", cleaned_input.lower())

        # Handle comma-separated names or suffixes:
        if "," in cleaned_input:
            parts = [p.strip() for p in cleaned_input.split(",") if p.strip()]
            if len(parts) == 2:
                # Check if second part is a suffix (e.g. "Bezaleel Paul, Ph.D." or "Paul, Jr.")
                p2_clean = re.sub(r"[^a-z0-9]", "", parts[1])
                if p2_clean in HONORIFIC_SUFFIXES:
                    cleaned_input = parts[0]
                else:
                    # Inverted format: "Paul, Bezaleel" -> "Bezaleel Paul"
                    cleaned_input = f"{parts[1]} {parts[0]}"

        # 1. Unicode decomposition
        nfkd = unicodedata.normalize("NFKD", cleaned_input)
        # 2. Strip non-ASCII diacritics
        ascii_text = nfkd.encode("ASCII", "ignore").decode("utf-8")
        # 3. Lowercase
        lowered = ascii_text.lower()
        # 4. Remove punctuation except spacing
        cleaned = re.sub(r"[^a-z0-9\s]", " ", lowered)
        raw_tokens = [t for t in cleaned.split() if t]

        # 5. Filter out honorifics / academic credentials
        filtered_tokens = [
            t for t in raw_tokens
            if t not in HONORIFIC_PREFIXES and t not in HONORIFIC_SUFFIXES
        ]

        # If filtering removed everything (e.g. name was just "Dr."), keep raw
        effective_tokens = filtered_tokens if filtered_tokens else raw_tokens
        normalized_str = " ".join(effective_tokens)
        return normalized_str, effective_tokens

    @staticmethod
    def normalize_name(name: str) -> str:
        norm_str, _ = IdentityMatcher.extract_cleaned_tokens(name)
        return norm_str

    def compare(self, student_name: str, recipient_name: str) -> IdentityMatchResult:
        norm_student, s_tokens = self.extract_cleaned_tokens(student_name)
        norm_recipient, r_tokens = self.extract_cleaned_tokens(recipient_name)

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
                reason="Exact match after normalization and title removal"
            )

        student_set = set(s_tokens)
        recipient_set = set(r_tokens)

        # 2. Token set equality (rearranged word order: "Paul Bezaleel" vs "Bezaleel Paul")
        if student_set == recipient_set and len(student_set) > 1:
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.HIGH_CONFIDENCE,
                similarity_score=0.98,
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason="Tokens match completely in rearranged order"
            )

        # 3. Substring / Subset match (middle name included or excluded)
        intersection = student_set.intersection(recipient_set)
        if len(intersection) >= 2 and (student_set.issubset(recipient_set) or recipient_set.issubset(student_set)):
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.HIGH_CONFIDENCE,
                similarity_score=0.92,
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason="Complete subset match (middle name present in one version)"
            )

        # 4. Initials matching (e.g. "B. Paul" vs "Bezaleel Paul")
        # Identify matched tokens
        unmatched_s = [t for t in s_tokens if t not in recipient_set]
        unmatched_r = [t for t in r_tokens if t not in student_set]

        # Check if unmatched tokens are valid initials matching corresponding full names
        if len(intersection) >= 1:
            # S has initial, R has full name
            s_initials_match = True
            if len(unmatched_s) > 0 and len(unmatched_s) == len(unmatched_r):
                for init_tok, full_tok in zip(unmatched_s, unmatched_r):
                    if len(init_tok) == 1 and full_tok.startswith(init_tok):
                        continue
                    elif len(full_tok) == 1 and init_tok.startswith(full_tok):
                        continue
                    else:
                        s_initials_match = False
                        break
                if s_initials_match:
                    return IdentityMatchResult(
                        match_level=IdentityMatchLevel.HIGH_CONFIDENCE,
                        similarity_score=0.92,
                        student_name=student_name,
                        recipient_name=recipient_name,
                        normalized_student=norm_student,
                        normalized_recipient=norm_recipient,
                        reason="Tokens match with valid initial abbreviation"
                    )

        # 5. Typo tolerance: Levenshtein distance on single-token or whole-string
        edit_dist = levenshtein_distance(norm_student, norm_recipient)
        max_len = max(len(norm_student), len(norm_recipient))
        ratio = 1.0 - (edit_dist / max_len) if max_len > 0 else 0.0

        if edit_dist <= 1 and max_len >= 5:
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.HIGH_CONFIDENCE,
                similarity_score=round(ratio, 2),
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason=f"Minor spelling discrepancy ({edit_dist} character difference)"
            )
        elif edit_dist == 2 and max_len >= 8:
            return IdentityMatchResult(
                match_level=IdentityMatchLevel.REVIEW,
                similarity_score=round(ratio, 2),
                student_name=student_name,
                recipient_name=recipient_name,
                normalized_student=norm_student,
                normalized_recipient=norm_recipient,
                reason=f"Slight spelling difference ({edit_dist} characters difference)"
            )

        # 6. Jaccard token overlap as fallback
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
            similarity_score=round(max(jaccard, ratio), 2),
            student_name=student_name,
            recipient_name=recipient_name,
            normalized_student=norm_student,
            normalized_recipient=norm_recipient,
            reason="Names differ significantly"
        )


identity_matcher = IdentityMatcher()
