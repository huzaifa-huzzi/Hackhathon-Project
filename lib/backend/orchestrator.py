"""
lib/backend/orchestrator.py
===========================
SikkaCheck — Async Pipeline Orchestrator

Runs all inspection layers concurrently for a given image path, collects
their LayerResults, and hands them to the synthesizer to produce a unified
PipelineResponse.

Layer registry
--------------
Each entry in LAYER_REGISTRY is a plain synchronous callable with the
signature:

    def run(image_path: str) -> LayerResult: ...

The orchestrator wraps every call in asyncio's thread-pool executor so the
layers run truly in parallel without blocking the event loop.

To add a new layer, implement its module and append an entry to
LAYER_REGISTRY — nothing else needs to change.
"""

from __future__ import annotations

import asyncio
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import Finding, LayerResult, LayerStatus, LayerVerdict, PipelineResponse
from .synthesizer import synthesize

# ---------------------------------------------------------------------------
# Layer adapter — wraps any existing inspection function into the shared schema
# ---------------------------------------------------------------------------


def _adapt_metadata_result(raw: Any) -> LayerResult:
    """
    Convert the LayerResult produced by metadata.py (which uses its own
    internal schema) into the canonical models.LayerResult.

    Once metadata.py is updated to import from models.py directly, this
    adapter becomes a no-op passthrough.
    """
    if isinstance(raw, LayerResult):
        return raw

    # Duck-type conversion from the old internal schema
    try:
        verdict_map = {
            "likely_real": LayerVerdict.AUTHENTIC,
            "authentic": LayerVerdict.AUTHENTIC,
            "inconclusive": LayerVerdict.INCONCLUSIVE,
            "suspicious": LayerVerdict.SUSPICIOUS,
            "rejected": LayerVerdict.REJECTED,
        }
        verdict_str = getattr(raw, "verdict", "inconclusive")
        verdict = verdict_map.get(str(verdict_str).lower(), LayerVerdict.INCONCLUSIVE)

        raw_findings = getattr(raw, "findings", []) or []
        findings = [
            Finding(
                type=getattr(f, "type", "unknown"),
                severity=getattr(f, "severity", "low"),
                message=getattr(f, "message", str(f)),
            )
            for f in raw_findings
        ]

        return LayerResult(
            layer="metadata",
            status=LayerStatus.SUCCESS,
            verdict=verdict,
            risk_score=float(getattr(raw, "risk_score", 0.5)),
            confidence=float(getattr(raw, "confidence", 0.5)),
            findings=findings,
            warnings=list(getattr(raw, "warnings", []) or []),
            evidence=dict(getattr(raw, "evidence", {}) or {}),
        )
    except Exception as exc:
        return _error_result("metadata", f"Failed to adapt metadata layer result: {exc}")


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
# Layer runner helpers
# ---------------------------------------------------------------------------


def _run_metadata_layer(image_path: str) -> LayerResult:
    """Invoke the metadata inspection layer and normalise its output."""
    try:
        from .metadata import inspect_metadata  # type: ignore[import]

        raw = inspect_metadata(image_path)
        return _adapt_metadata_result(raw)
    except ImportError:
        return _skipped_result("metadata", "metadata.py module not found")
    except Exception as exc:
        tb = traceback.format_exc()
        return _error_result("metadata", f"Unhandled exception: {exc}\n{tb}")


def _run_pixel_signal_layer(image_path: str) -> LayerResult:
    """Invoke the pixel & signal forensics layer."""
    try:
        from .pixel_signal import inspect_pixel_signal  # type: ignore[import]

        raw = inspect_pixel_signal(image_path)
        if isinstance(raw, LayerResult):
            return raw
        return _adapt_metadata_result(raw)  # fallback duck-type
    except ImportError:
        return _skipped_result("pixel_signal", "pixel_signal.py module not found")
    except Exception as exc:
        tb = traceback.format_exc()
        return _error_result("pixel_signal", f"Unhandled exception: {exc}\n{tb}")


def _run_structural_layer(image_path: str) -> LayerResult:
    """Invoke the structural / reconciliation layer."""
    try:
        # Support either naming convention
        try:
            from .structural import inspect_structural  # type: ignore[import]

            raw = inspect_structural(image_path)
        except ImportError:
            from .reconciliation import inspect_reconciliation  # type: ignore[import]

            raw = inspect_reconciliation(image_path)

        if isinstance(raw, LayerResult):
            return raw
        return _adapt_metadata_result(raw)
    except ImportError:
        return _skipped_result(
            "structural", "structural.py / reconciliation.py module not found"
        )
    except Exception as exc:
        tb = traceback.format_exc()
        return _error_result("structural", f"Unhandled exception: {exc}\n{tb}")


# ---------------------------------------------------------------------------
# Layer registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _LayerEntry:
    name: str
    runner: Callable[[str], LayerResult]
    enabled: bool = True


LAYER_REGISTRY: list[_LayerEntry] = [
    _LayerEntry(name="metadata", runner=_run_metadata_layer),
    _LayerEntry(name="pixel_signal", runner=_run_pixel_signal_layer),
    _LayerEntry(name="structural", runner=_run_structural_layer),
]


# ---------------------------------------------------------------------------
# Async core
# ---------------------------------------------------------------------------


async def _run_layer_async(
    entry: _LayerEntry,
    image_path: str,
    loop: asyncio.AbstractEventLoop,
) -> tuple[str, LayerResult]:
    """
    Run a single synchronous layer function in the thread-pool executor
    so it doesn't block the event loop.

    Returns (layer_name, LayerResult).
    """
    if not entry.enabled:
        return entry.name, _skipped_result(entry.name, "Layer is disabled in registry")

    try:
        result: LayerResult = await loop.run_in_executor(
            None, entry.runner, image_path
        )
        return entry.name, result
    except Exception as exc:
        tb = traceback.format_exc()
        return entry.name, _error_result(
            entry.name, f"Executor exception: {exc}\n{tb}"
        )


async def run_pipeline_async(image_path: str) -> PipelineResponse:
    """
    Execute all registered layers concurrently and synthesize a verdict.

    Parameters
    ----------
    image_path:
        Absolute or relative path to the image file.

    Returns
    -------
    PipelineResponse
        Unified forensic verdict with per-layer results.
    """
    loop = asyncio.get_event_loop()

    tasks = [
        _run_layer_async(entry, image_path, loop)
        for entry in LAYER_REGISTRY
    ]

    pairs: list[tuple[str, LayerResult]] = await asyncio.gather(*tasks)
    layer_results: dict[str, LayerResult] = dict(pairs)

    return synthesize(layer_results)


# ---------------------------------------------------------------------------
# Synchronous convenience wrapper (useful for scripts / tests)
# ---------------------------------------------------------------------------


def run_pipeline(image_path: str) -> PipelineResponse:
    """
    Blocking wrapper around run_pipeline_async.

    Prefer calling run_pipeline_async directly from async contexts (e.g.
    FastAPI route handlers) to avoid event-loop conflicts.

    Parameters
    ----------
    image_path:
        Absolute or relative path to the image file.

    Returns
    -------
    PipelineResponse
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already inside a running loop (e.g. Jupyter) — create a task
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    lambda: asyncio.run(run_pipeline_async(image_path))
                )
                return future.result()
        return loop.run_until_complete(run_pipeline_async(image_path))
    except RuntimeError:
        return asyncio.run(run_pipeline_async(image_path))
