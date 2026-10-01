import hashlib
from typing import List, Optional
from pydantic import BaseModel
from PIL import Image
from app.models import DuplicateMatchType


class DuplicateDetectionResult(BaseModel):
    has_duplicate: bool
    matches: List[dict] = []


class DuplicateDetector:
    """
    Detects exact, perceptual, certificate ID, and OCR duplicates across submissions.
    """

    @staticmethod
    def compute_image_dhash(image_path: str, hash_size: int = 8) -> Optional[str]:
        """Calculates difference hash (dHash) for visual perceptual similarity."""
        try:
            with Image.open(image_path) as img:
                img = img.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
                pixels = list(img.getdata())
                # Compare adjacent pixels
                diff = []
                for row in range(hash_size):
                    for col in range(hash_size):
                        pixel_left = pixels[row * (hash_size + 1) + col]
                        pixel_right = pixels[row * (hash_size + 1) + col + 1]
                        diff.append(pixel_left > pixel_right)
                
                # Convert binary array to hex string
                decimal_val = 0
                hex_str = []
                for index, val in enumerate(diff):
                    if val:
                        decimal_val += 2 ** (index % 4)
                    if (index % 4) == 3:
                        hex_str.append(hex(decimal_val)[2:])
                        decimal_val = 0
                return "".join(hex_str)
        except Exception:
            return None

    @staticmethod
    def compute_hamming_distance(hash1: str, hash2: str) -> int:
        """Hamming distance between two hex perceptual hashes."""
        if not hash1 or not hash2 or len(hash1) != len(hash2):
            return 999
        bin1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
        bin2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
        return sum(c1 != c2 for c1, c2 in zip(bin1, bin2))

    @staticmethod
    def compute_text_similarity(text1: str, text2: str) -> float:
        """Calculates Jaccard token similarity of OCR text."""
        if not text1 or not text2:
            return 0.0
        tokens1 = set(text1.lower().split())
        tokens2 = set(text2.lower().split())
        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)
        return len(intersection) / len(union) if union else 0.0


duplicate_detector = DuplicateDetector()
