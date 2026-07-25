from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class LayerStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class LayerVerdict(str, Enum):
    LIKELY_REAL = "likely_real"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Finding(BaseModel):
    type: str = Field(..., description="Detector/category that produced this finding")
    severity: FindingSeverity
    message: str


class LayerResult(BaseModel):
    layer: str = Field(
        ..., description="Layer identifier (ocr, metadata, pixel_signal, structural)"
    )

    status: LayerStatus

    verdict: LayerVerdict

    risk_score: float = Field(
        ..., ge=0.0, le=1.0, description="0 = trustworthy, 1 = highly suspicious"
    )

    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in this layer's own assessment"
    )

    findings: list[Finding] = Field(default_factory=list)

    warnings: list[str] = Field(default_factory=list)

    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Detector-specific structured evidence"
    )
