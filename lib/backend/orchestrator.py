"""
lib/backend/orchestrator.py
===========================
SikkaCheck — Async Pipeline Orchestrator

Runs all three inspection layers concurrently, normalises their outputs
into the canonical models.LayerResult schema, then calls the synthesizer
to produce a single PipelineResponse.

Layer inventory
---------------
Layer 1 – metadata        : lib/backend/metadata.py
    Function : inspect_metadata(image_path: str) -> internal Pydantic LayerResult
    Returns  : Pydantic model with fields layer_name, verdict (str), risk_score,
               confidence, findings (Pydantic list), warnings, evidence

Layer 2 – pixel_signal    : lib/backend/pixel_signal_analyzer.py
    Function : inspect_pixel_signals(image_path: str) -> dataclass LayerResult
    Returns  : Dataclass with fields layer_name, verdict (str), risk_score,
               confidence, findings (dataclass list), warnings, evidence

Layer 3 – structural      : lib/backend/structural_analyzer.py
    Function : inspect_structural(image_path, ocr_data=None) -> dataclass LayerResult
    Returns  : Dataclass with fields layer_name, verdict (str), risk_score,
               confidence, findings (dataclass list), warnings, evidence
               ocr_data is optional; pchatgptass None when not available.

Each layer uses its own local Finding / LayerResult types (not the shared
models). The orchestrator adapts every output into models.LayerResult before
passing results to the synthesizer.
"""

from __future__ import annotations

import asyncio
import traceback
from typing import Any

try:
    from .models import Finding, LayerResult, LayerStatus, LayerVerdict, PipelineResponse
    from .synthesizer import synthesize
except ImportError:
    from models import Finding, LayerResult, LayerStatus, LayerVerdict, PipelineResponse  # type: ignore[no-redef]
    from synthesizer import synthesize  # type: ignore[no-redef]

# ---------------------------------------------------------------------------
# Shared adapter utilities
# ---------------------------------------------------------------------------

_VERDICT_MAP: dict[str, LayerVerdict] = {
    "likely_real": LayerVerdict.AUTHENTIC,
    "authentic": LayerVerdict.AUTHENTIC,
    "inconclusive": LayerVerdict.INCONCLUSIVE,
    "suspicious": LayerVerdict.SUSPICIOUS,
    "rejected": LayerVerdict.REJECTED,
}


def _map_verdict(raw_verdict: str) -> LayerVerdict:
    return _VERDICT_MAP.get(str(raw_verdict).lower(), LayerVerdict.INCONCLUSIVE)


def _adapt_findings(raw_findings: list[Any]) -> list[Finding]:
    """Convert any Finding-like objects (dataclass or Pydantic) to models.Finding."""
    out: list[Finding] = []
    for f in raw_findings or []:
        try:
            out.append(
                Finding(
                    type=str(getattr(f, "type", "unknown")),
                    severity=str(getattr(f, "severity", "low")),
                    message=str(getattr(f, "message", "")),
                )
            )
        except Exception:
            pass
    return out


def _adapt_layer_result(raw: Any, layer_name: str) -> LayerResult:
    """
    Normalise any layer's output into the canonical models.LayerResult.

    Handles:
    - Already-canonical models.LayerResult (passthrough)
    - Pydantic models with layer_name / verdict fields (metadata.py)
    - Dataclasses with layer_name / verdict fields (pixel_signal, structural)
    """
    if isinstance(raw, LayerResult):
        return raw

    try:
        raw_verdict = getattr(raw, "verdict", "inconclusive")
        verdict = _map_verdict(raw_verdict)

        warnings: list[str] = list(getattr(raw, "warnings", []) or [])
        status = LayerStatus.WARNING if warnings else LayerStatus.SUCCESS

        return LayerResult(
            layer=layer_name,
            status=status,
            verdict=verdict,
            risk_score=float(getattr(raw, "risk_score", 0.5)),
            confidence=float(getattr(raw, "confidence", 0.5)),
            findings=_adapt_findings(getattr(raw, "findings", [])),
            warnings=warnings,
            evidence=dict(getattr(raw, "evidence", {}) or {}),
        )
    except Exception as exc:
        return _error_result(layer_name, f"Failed to adapt layer result: {exc}")


# ---------------------------------------------------------------------------
# Error / skip result factories
# ---------------------------------------------------------------------------


def _error_result(layer_name: str, message: str) -> LayerResult:
    return LayerResult(
        layer=layer_name,
        status=LayerStatus.ERROR,
        verdict=LayerVerdict.INCONCLUSIVE,
        risk_score=0.5,
        confidence=0.0,
        findings=[Finding(type="layer_error", severity="high", message=message)],
        warnings=[message],
        evidence={},
    )


def _skipped_result(layer_name: str, reason: str) -> LayerResult:
    return LayerResult(
        layer=layer_name,
        status=LayerStatus.SKIPPED,
        verdict=LayerVerdict.INCONCLUSIVE,
        risk_score=0.5,
        confidence=0.0,
        findings=[],
        warnings=[f"Layer skipped: {reason}"],
        evidence={},
    )


# ---------------------------------------------------------------------------
# Layer runner functions — one per layer
# Each runner imports from the correct module, calls the correct function,
# and adapts the result into models.LayerResult.
# ---------------------------------------------------------------------------


def _run_metadata_layer(image_path: str) -> LayerResult:
    """
    Layer 1: Metadata & EXIF inspection.
    Module  : lib/backend/metadata.py
    Function: inspect_metadata(image_path: str)
    """
    try:
        try:
            from .metadata import inspect_metadata  # type: ignore[import]
        except ImportError:
            from metadata import inspect_metadata  # type: ignore[no-redef]

        raw = inspect_metadata(image_path)
        return _adapt_layer_result(raw, "metadata")
    except ImportError as exc:
        return _skipped_result("metadata", f"metadata.py not importable: {exc}")
    except Exception as exc:
        return _error_result("metadata", f"Unhandled exception: {exc}\n{traceback.format_exc()}")


def _run_pixel_signal_layer(image_path: str) -> LayerResult:
    """
    Layer 2: Pixel & Signal Forensics (FFT, ELA, noise grid).
    Module  : lib/backend/pixel_signal_analyzer.py
    Function: inspect_pixel_signals(image_path: str)   ← note the plural 's'
    """
    try:
        try:
            from .pixel_signal_analyzer import inspect_pixel_signals  # type: ignore[import]
        except ImportError:
            from pixel_signal_analyzer import inspect_pixel_signals  # type: ignore[no-redef]

        raw = inspect_pixel_signals(image_path)
        return _adapt_layer_result(raw, "pixel_signal")
    except ImportError as exc:
        return _skipped_result("pixel_signal", f"pixel_signal_analyzer.py not importable: {exc}")
    except Exception as exc:
        return _error_result("pixel_signal", f"Unhandled exception: {exc}\n{traceback.format_exc()}")


def _run_structural_layer(
    image_path: str,
    ocr_data: list[dict[str, Any]] | None = None,
) -> LayerResult:
    """
    Layer 3: Structural & Geometric analysis.
    Module  : lib/backend/structural_analyzer.py
    Function: inspect_structural(image_path, ocr_data=None)
    ocr_data: Optional pre-computed OCR bounding boxes. Pass None when
              OCR results are not available — the layer degrades gracefully.
    """
    try:
        try:
            from .structural_analyzer import inspect_structural  # type: ignore[import]
        except ImportError:
            from structural_analyzer import inspect_structural  # type: ignore[no-redef]

        raw = inspect_structural(image_path, ocr_data=ocr_data)
        return _adapt_layer_result(raw, "structural")
    except ImportError as exc:
        return _skipped_result("structural", f"structural_analyzer.py not importable: {exc}")
    except Exception as exc:
        return _error_result("structural", f"Unhandled exception: {exc}\n{traceback.format_exc()}")


# ---------------------------------------------------------------------------
# Async core
# ---------------------------------------------------------------------------


async def run_pipeline_async(
    image_path: str,
    ocr_data: list[dict[str, Any]] | None = None,
) -> PipelineResponse:
    """
    Run all three inspection layers concurrently and synthesize a verdict.

    Parameters
    ----------
    image_path:
        Absolute or relative path to the image file on disk.
    ocr_data:
        Optional pre-computed OCR bounding-box data forwarded to the
        structural layer. Each element should be a dict with keys:
            {"text": str, "bbox": [x, y, w, h], "confidence": float}
        Pass None (default) when OCR data is not available.

    Returns
    -------
    PipelineResponse
        Unified forensic verdict with per-layer results.
    """
    loop = asyncio.get_event_loop()

    # Wrap each synchronous layer in run_in_executor so they run in parallel
    # without blocking the event loop.
    metadata_task = loop.run_in_executor(None, _run_metadata_layer, image_path)
    pixel_task = loop.run_in_executor(None, _run_pixel_signal_layer, image_path)
    # structural needs ocr_data — use a lambda to bind the extra arg
    structural_task = loop.run_in_executor(
        None, lambda: _run_structural_layer(image_path, ocr_data)
    )

    metadata_result, pixel_result, structural_result = await asyncio.gather(
        metadata_task,
        pixel_task,
        structural_task,
    )

    layer_results: dict[str, LayerResult] = {
        "metadata": metadata_result,
        "pixel_signal": pixel_result,
        "structural": structural_result,
    }

    return synthesize(layer_results)


# ---------------------------------------------------------------------------
# Synchronous convenience wrapper
# ---------------------------------------------------------------------------


def run_pipeline(
    image_path: str,
    ocr_data: list[dict[str, Any]] | None = None,
) -> PipelineResponse:
    """
    Blocking wrapper around run_pipeline_async.

    Use run_pipeline_async directly from async contexts (e.g. FastAPI route
    handlers using `await`) to avoid event-loop nesting issues.

    Parameters
    ----------
    image_path:
        Absolute or relative path to the image file.
    ocr_data:
        Optional OCR bounding-box data for the structural layer.

    Returns
    -------
    PipelineResponse
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Inside an already-running loop (e.g. Jupyter / nested async)
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    lambda: asyncio.run(run_pipeline_async(image_path, ocr_data))
                )
                return future.result()
        return loop.run_until_complete(run_pipeline_async(image_path, ocr_data))
    except RuntimeError:
        return asyncio.run(run_pipeline_async(image_path, ocr_data))
