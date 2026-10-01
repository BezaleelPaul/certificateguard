from abc import ABC, abstractmethod
from enum import Enum
from pydantic import BaseModel
from typing import Optional, Dict, Any


class SyntheticSignal(str, Enum):
    NO_STRONG_SIGNAL = "NO_STRONG_SIGNAL"
    SUSPICIOUS = "SUSPICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class DetectorResult(BaseModel):
    signal: SyntheticSignal
    confidence: float = 0.5
    model_name: str = "heuristic_baseline"
    details: str = "Synthetic document analysis is supporting evidence only and does not establish authenticity."
    metadata: Dict[str, Any] = {}


class SyntheticDocumentDetector(ABC):
    @abstractmethod
    async def analyze(self, file_path: str) -> DetectorResult:
        """Analyzes document for AI / synthetic generation artifacts."""
        pass


class DefaultSyntheticDetector(SyntheticDocumentDetector):
    """
    Default offline synthetic detector. Returns INCONCLUSIVE by default,
    adhering strictly to the security principle that AI detection alone must NEVER
    be treated as proof of authenticity or fakery.
    """

    async def analyze(self, file_path: str) -> DetectorResult:
        # Initial offline baseline
        return DetectorResult(
            signal=SyntheticSignal.INCONCLUSIVE,
            confidence=0.5,
            model_name="default_offline_baseline",
            details="AI detection is a supporting signal only. Analysis concluded as inconclusive.",
            metadata={"status": "completed"}
        )


synthetic_detector = DefaultSyntheticDetector()
