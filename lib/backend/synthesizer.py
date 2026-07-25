"""
lib/backend/synthesizer.py
==========================
SikkaCheck — Decision Synthesizer

Receives all LayerResults from the orchestrator and produces a single
PipelineResponse with a weighted risk score, overall verdict, confidence,
summary narrative, and circuit-breaker flag.
"""

from __future__ import annotations

from typing import Sequence

try:
    from .models import LayerResult, LayerStatus, LayerVerdict, PipelineResponse
except ImportError:
    from models import LayerResult, LayerStatus, LayerVerdict, PipelineResponse  # type: ignore[no-redef]

# ---------------------------------------------------------------------------
# Layer weights — must sum to 1.0.
# Adjust here when layer reliability changes.
# ---------------------------------------------------------------------------

LAYER_WEIGHTS: dict[str, float] = {
    "metadata": 0.30,
    "pixel_signal": 0.40,
    "structural": 0.20,
    "reconciliation": 0.10,
}

# Weight used for any layer whose name is not in LAYER_WEIGHTS above.
_DEFAULT_WEIGHT: float = 0.20

# ---------------------------------------------------------------------------
# Verdict thresholds (applied to weighted risk score)
# ---------------------------------------------------------------------------

_AUTHENTIC_CEILING: float = 0.30
_SUSPICIOUS_FLOOR: float = 0.55

# ---------------------------------------------------------------------------
# Circuit-breaker threshold
# A single layer can trigger an immediate REJECTED verdict when its
# risk_score AND confidence are both above these values.
# ---------------------------------------------------------------------------

_CIRCUIT_RISK_THRESHOLD: float = 0.90
_CIRCUIT_CONFIDENCE_THRESHOLD: float = 0.70


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _weight_for(layer_name: str) -> float:
    """Return the configured weight for a layer, falling back to the default."""
    return LAYER_WEIGHTS.get(layer_name, _DEFAULT_WEIGHT)


def _normalised_weights(results: dict[str, LayerResult]) -> dict[str, float]:
    """
    Compute per-layer weights normalised so they sum to 1.0.

    Only layers with status SUCCESS or WARNING contribute to the score.
    SKIPPED and ERROR layers are excluded but the weights are redistributed
    among the remaining layers proportionally.
    """
    scoreable = {
        name: result
        for name, result in results.items()
        if result.status in (LayerStatus.SUCCESS, LayerStatus.WARNING)
    }

    raw: dict[str, float] = {name: _weight_for(name) for name in scoreable}
    total = sum(raw.values())

    if total == 0.0:
        # Degenerate case — give every scoreable layer equal weight
        equal = 1.0 / len(scoreable) if scoreable else 1.0
        return {name: equal for name in scoreable}

    return {name: w / total for name, w in raw.items()}


def _weighted_risk(
    results: dict[str, LayerResult],
    weights: dict[str, float],
) -> float:
    """Compute confidence-weighted, layer-weighted aggregate risk score."""
    score = 0.0
    total_conf_weight = 0.0

    for name, result in results.items():
        w = weights.get(name, 0.0)
        if w == 0.0:
            continue
        effective = w * result.confidence
        score += effective * result.risk_score
        total_conf_weight += effective

    if total_conf_weight == 0.0:
        # No confidence anywhere — take simple average
        values = [r.risk_score for r in results.values()]
        return sum(values) / len(values) if values else 0.5

    return round(score / total_conf_weight, 4)


def _weighted_confidence(
    results: dict[str, LayerResult],
    weights: dict[str, float],
) -> float:
    """Compute weighted average confidence across contributing layers."""
    total_w = 0.0
    total_wc = 0.0
    for name, result in results.items():
        w = weights.get(name, 0.0)
        total_w += w
        total_wc += w * result.confidence

    if total_w == 0.0:
        return 0.0
    return round(total_wc / total_w, 4)


def _circuit_breaker_triggered(results: dict[str, LayerResult]) -> str | None:
    """
    Return the layer name that triggered the circuit breaker, or None.

    A layer triggers the circuit breaker when its risk_score AND confidence
    both exceed their respective thresholds.
    """
    for name, result in results.items():
        if (
            result.status in (LayerStatus.SUCCESS, LayerStatus.WARNING)
            and result.risk_score >= _CIRCUIT_RISK_THRESHOLD
            and result.confidence >= _CIRCUIT_CONFIDENCE_THRESHOLD
        ):
            return name
    return None


def _determine_verdict(risk_score: float) -> LayerVerdict:
    if risk_score < _AUTHENTIC_CEILING:
        return LayerVerdict.AUTHENTIC
    if risk_score < _SUSPICIOUS_FLOOR:
        return LayerVerdict.INCONCLUSIVE
    return LayerVerdict.SUSPICIOUS


def _build_summary(
    verdict: LayerVerdict,
    risk_score: float,
    confidence: float,
    results: dict[str, LayerResult],
    circuit_layer: str | None,
) -> str:
    """Generate a human-readable summary of the pipeline decision."""
    layer_lines: list[str] = []
    for name, r in results.items():
        status_tag = r.status.value.upper()
        layer_lines.append(
            f"  • {name} [{status_tag}]: verdict={r.verdict.value}, "
            f"risk={r.risk_score:.2f}, confidence={r.confidence:.2f}"
        )
    layers_block = "\n".join(layer_lines) if layer_lines else "  • No layers ran."

    if circuit_layer:
        intro = (
            f"REJECTED — circuit breaker triggered by the '{circuit_layer}' layer "
            f"(risk={results[circuit_layer].risk_score:.2f}, "
            f"confidence={results[circuit_layer].confidence:.2f})."
        )
    elif verdict == LayerVerdict.AUTHENTIC:
        intro = (
            f"The image appears AUTHENTIC. "
            f"Weighted risk score: {risk_score:.2f} (confidence: {confidence:.2f})."
        )
    elif verdict == LayerVerdict.SUSPICIOUS:
        intro = (
            f"The image is SUSPICIOUS. "
            f"Weighted risk score: {risk_score:.2f} (confidence: {confidence:.2f})."
        )
    else:
        intro = (
            f"The result is INCONCLUSIVE. "
            f"Weighted risk score: {risk_score:.2f} (confidence: {confidence:.2f}). "
            f"Further review is recommended."
        )

    return f"{intro}\n\nLayer breakdown:\n{layers_block}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def synthesize(layer_results: dict[str, LayerResult]) -> PipelineResponse:
    """
    Combine all LayerResults into a single PipelineResponse.

    Parameters
    ----------
    layer_results:
        Mapping of layer name → LayerResult, as produced by the orchestrator.

    Returns
    -------
    PipelineResponse
        Unified pipeline decision with overall verdict, risk score, confidence,
        summary, circuit-breaker flag, and the full per-layer results.
    """
    if not layer_results:
        return PipelineResponse(
            overall_verdict=LayerVerdict.INCONCLUSIVE,
            overall_risk_score=0.5,
            overall_confidence=0.0,
            summary="No layers ran — pipeline produced no results.",
            circuit_breaker_triggered=False,
            layer_results={},
        )

    # ── Circuit breaker check (before weighted scoring) ───────────────────
    circuit_layer = _circuit_breaker_triggered(layer_results)
    if circuit_layer:
        cb_result = layer_results[circuit_layer]
        summary = _build_summary(
            LayerVerdict.REJECTED,
            cb_result.risk_score,
            cb_result.confidence,
            layer_results,
            circuit_layer,
        )
        return PipelineResponse(
            overall_verdict=LayerVerdict.REJECTED,
            overall_risk_score=round(cb_result.risk_score, 4),
            overall_confidence=round(cb_result.confidence, 4),
            summary=summary,
            circuit_breaker_triggered=True,
            layer_results=layer_results,
        )

    # ── Weighted scoring ──────────────────────────────────────────────────
    weights = _normalised_weights(layer_results)
    risk_score = _weighted_risk(layer_results, weights)
    confidence = _weighted_confidence(layer_results, weights)
    verdict = _determine_verdict(risk_score)

    summary = _build_summary(verdict, risk_score, confidence, layer_results, None)

    return PipelineResponse(
        overall_verdict=verdict,
        overall_risk_score=risk_score,
        overall_confidence=confidence,
        summary=summary,
        circuit_breaker_triggered=False,
        layer_results=layer_results,
    )
