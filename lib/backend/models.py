"""
lib/backend/models.py
=====================
SikkaCheck — shared Pydantic schema used by every layer and the pipeline.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class LayerStatus(str, Enum):
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


class LayerVerdict(str, Enum):
    AUTHENTIC = "authentic"
    INCONCLUSIVE = "inconclusive"
    SUSPICIOUS = "suspicious"
    REJECTED = "rejected"


class Finding(BaseModel):
    type: str
    severity: str  # "low" | "medium" | "high" | "critical"
    message: str


class LayerResult(BaseModel):
    layer: str = Field(
        ...,
        description="Layer identifier (metadata, pixel_signal, structural, reconciliation)",
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
        default_factory=dict,
        description="Detector-specific structured evidence",
    )


class PipelineResponse(BaseModel):
    overall_verdict: LayerVerdict
    overall_risk_score: float = Field(..., ge=0.0, le=1.0)
    overall_confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    circuit_breaker_triggered: bool = False
    layer_results: dict[str, LayerResult]
