"""
lib/backend/metadata.py
=======================
SikkaCheck — Metadata Inspection Layer

Performs forensic analysis of image metadata to assess whether an image
is likely real, suspicious, possibly AI-generated, or inconclusive.

Rules:
  - Metadata only — no pixel inspection, no OCR, no ML models.
  - ExifTool is the primary extractor; Pillow + exifread are the fallback.
  - Never crashes on malformed metadata; all errors become warnings.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import warnings as _warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Optional imports (graceful degradation)
# ---------------------------------------------------------------------------
try:
    from PIL import Image as _PilImage
    from PIL.ExifTags import TAGS as _PIL_TAGS

    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    import exifread as _exifread

    _EXIFREAD_AVAILABLE = True
except ImportError:
    _EXIFREAD_AVAILABLE = False


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single structured forensic observation."""

    type: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    message: str


class LayerResult(BaseModel):
    """Standardised output produced by every SikkaCheck forensic layer."""

    layer_name: str
    verdict: str  # "likely_real" | "inconclusive" | "suspicious"
    risk_score: float  # 0.0 – 1.0
    confidence: float  # 0.0 – 1.0
    findings: list[Finding]
    warnings: list[str]
    evidence: dict[str, Any]


# ---------------------------------------------------------------------------
# Configuration — easily extendable lists
# ---------------------------------------------------------------------------

#: Keywords that indicate an AI image-generation tool.
AI_SIGNATURES: list[str] = [
    "stable diffusion",
    "stablediffusion",
    "sdxl",
    "flux",
    "comfyui",
    "comfy ui",
    "automatic1111",
    "a1111",
    "fooocus",
    "invokeai",
    "invoke ai",
    "midjourney",
    "dall-e",
    "dall·e",
    "dalle",
    "leonardo ai",
    "ideogram",
    "firefly",
    "adobe firefly",
    "nightcafe",
    "dreamstudio",
    "playgroundai",
    "playground ai",
    "novelai",
    "novel ai",
    "civitai",
    "tensorart",
    "seaart",
    "bing image creator",
    "designer",
    "generative fill",
    "ai generated",
    "diffusion",
    "lora",
    "vae",
    "cfg scale",
    "sampling steps",
    "seed:",
]

#: Keywords that identify real consumer device / OS origins.
DEVICE_SIGNATURES: list[tuple[str, str]] = [
    # (keyword_lower, canonical_label)
    ("android", "Android"),
    ("samsung", "Samsung"),
    ("xiaomi", "Xiaomi"),
    ("redmi", "Xiaomi Redmi"),
    ("hyperos", "HyperOS (Xiaomi)"),
    ("miui", "MIUI (Xiaomi)"),
    ("oppo", "Oppo"),
    ("vivo", "Vivo"),
    ("oneplus", "OnePlus"),
    ("one ui", "One UI (Samsung)"),
    ("google pixel", "Google Pixel"),
    ("pixel", "Google Pixel"),
    ("iphone", "iPhone"),
    ("ios", "iOS"),
    ("apple", "Apple"),
    ("ipad", "iPad"),
    ("macos", "macOS"),
    ("windows phone", "Windows Phone"),
    ("nokia", "Nokia"),
    ("motorola", "Motorola"),
    ("huawei", "Huawei"),
    ("honor", "Honor"),
    ("realme", "Realme"),
    ("tecno", "Tecno"),
    ("infinix", "Infinix"),
    ("asus", "Asus"),
    ("lg electronics", "LG"),
    ("sony", "Sony"),
]

#: Keywords that identify known image-editing software.
EDITING_SIGNATURES: list[tuple[str, str]] = [
    ("adobe photoshop", "Adobe Photoshop"),
    ("photoshop", "Adobe Photoshop"),
    ("adobe lightroom", "Adobe Lightroom"),
    ("lightroom", "Adobe Lightroom"),
    ("adobe illustrator", "Adobe Illustrator"),
    ("gimp", "GIMP"),
    ("canva", "Canva"),
    ("snapseed", "Snapseed"),
    ("affinity photo", "Affinity Photo"),
    ("affinity designer", "Affinity Designer"),
    ("paint.net", "Paint.NET"),
    ("figma", "Figma"),
    ("pixlr", "Pixlr"),
    ("fotor", "Fotor"),
    ("facetune", "Facetune"),
    ("meitu", "Meitu"),
    ("picsart", "PicsArt"),
    ("vsco", "VSCO"),
    ("capture one", "Capture One"),
    ("darktable", "Darktable"),
    ("rawtherapee", "RawTherapee"),
    ("luminar", "Luminar"),
    ("on1 photo", "ON1 Photo RAW"),
    ("skylum", "Skylum"),
    ("corel", "Corel"),
    ("paint shop pro", "Paint Shop Pro"),
    ("inkscape", "Inkscape"),
]


# ---------------------------------------------------------------------------
# Internal state container (not exposed externally)
# ---------------------------------------------------------------------------


@dataclass
class _AnalysisState:
    """Mutable accumulator used throughout the analysis pipeline."""

    raw_metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    risk_delta: float = 0.0      # cumulative adjustment to risk score
    confidence_delta: float = 0.0  # cumulative adjustment to confidence
    metadata_richness: int = 0   # count of meaningful fields found

    # Evidence fields
    metadata_present: bool = False
    real_device_metadata_detected: bool = False
    ai_metadata_detected: bool = False
    editing_software_detected: bool = False
    software: str | None = None
    device: str | None = None
    camera_make: str | None = None
    camera_model: str | None = None

    def add_finding(self, type_: str, severity: str, message: str) -> None:
        self.findings.append(Finding(type=type_, severity=severity, message=message))

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def _run_exiftool(image_path: str) -> dict[str, Any] | None:
    """
    Run ExifTool and return parsed JSON output.

    Returns None if ExifTool is not installed or fails.
    """
    try:
        result = subprocess.run(
            ["exiftool", "-json", "-a", "-u", "-g", image_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list) and data:
                return data[0]
    except FileNotFoundError:
        pass  # ExifTool not installed — caller will fall back
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
        _warnings.warn(f"ExifTool error: {exc}")
    return None


def _extract_via_pillow(image_path: str, state: _AnalysisState) -> dict[str, Any]:
    """Extract metadata using Pillow as a fallback."""
    meta: dict[str, Any] = {}
    if not _PIL_AVAILABLE:
        state.add_warning("Pillow is not installed; skipping Pillow extraction.")
        return meta
    try:
        with _PilImage.open(image_path) as img:
            meta["File:ImageWidth"] = img.width
            meta["File:ImageHeight"] = img.height
            meta["File:ColorMode"] = img.mode

            info = img.info or {}

            # DPI
            dpi = info.get("dpi")
            if dpi:
                meta["File:XResolution"] = dpi[0]
                meta["File:YResolution"] = dpi[1]

            # Raw EXIF via Pillow
            exif_data = img._getexif() if hasattr(img, "_getexif") else None  # type: ignore[attr-defined]
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = _PIL_TAGS.get(tag_id, str(tag_id))
                    meta[f"EXIF:{tag_name}"] = (
                        str(value) if not isinstance(value, (str, int, float)) else value
                    )

            # ICC profile name
            icc = info.get("icc_profile")
            if icc:
                meta["ICC_Profile:Present"] = True

            # XMP / other blobs stored in info
            for k, v in info.items():
                if k not in ("dpi", "icc_profile", "exif") and isinstance(v, str):
                    meta[f"File:Info:{k}"] = v
    except Exception as exc:
        state.add_warning(f"Pillow extraction error: {exc}")
    return meta


def _extract_via_exifread(image_path: str, state: _AnalysisState) -> dict[str, Any]:
    """Extract EXIF metadata using exifread as a secondary fallback."""
    meta: dict[str, Any] = {}
    if not _EXIFREAD_AVAILABLE:
        state.add_warning("exifread is not installed; skipping exifread extraction.")
        return meta
    try:
        with open(image_path, "rb") as fh:
            tags = _exifread.process_file(fh, details=True)
        for tag, value in tags.items():
            meta[f"EXIF:{tag}"] = str(value)
    except Exception as exc:
        state.add_warning(f"exifread extraction error: {exc}")
    return meta


def _extract_file_info(image_path: str, state: _AnalysisState) -> dict[str, Any]:
    """Collect basic file-system level metadata."""
    meta: dict[str, Any] = {}
    try:
        stat = os.stat(image_path)
        meta["File:FileSize"] = stat.st_size
        meta["File:FileName"] = os.path.basename(image_path)
        _, ext = os.path.splitext(image_path)
        meta["File:FileExtension"] = ext.lstrip(".").lower()

        import mimetypes

        mime, _ = mimetypes.guess_type(image_path)
        if mime:
            meta["File:MIMEType"] = mime
    except Exception as exc:
        state.add_warning(f"File info extraction error: {exc}")
    return meta


def _extract_metadata(image_path: str, state: _AnalysisState) -> dict[str, Any]:
    """
    Extract metadata using ExifTool → Pillow → exifread cascade.

    Always supplements with basic file info.
    """
    combined: dict[str, Any] = {}

    # File-system info is always available
    combined.update(_extract_file_info(image_path, state))

    exiftool_result = _run_exiftool(image_path)
    if exiftool_result:
        # ExifTool returns a nested dict grouped by category
        for group, fields in exiftool_result.items():
            if isinstance(fields, dict):
                for k, v in fields.items():
                    combined[f"{group}:{k}"] = v
            else:
                combined[group] = fields
        state.add_warning(None)  # sentinel cleared below
    else:
        state.add_warning(
            "ExifTool unavailable or returned no output; using Pillow + exifread fallback."
        )
        combined.update(_extract_via_pillow(image_path, state))
        combined.update(_extract_via_exifread(image_path, state))

    # Remove the sentinel None that may have been added
    state.warnings = [w for w in state.warnings if w is not None]

    return combined


# ---------------------------------------------------------------------------
# Helper: flatten metadata to searchable text blob
# ---------------------------------------------------------------------------


def _flatten_to_text(metadata: dict[str, Any]) -> str:
    """Produce a single lowercase string from all metadata values for pattern matching."""
    parts: list[str] = []
    for v in metadata.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (int, float)):
            parts.append(str(v))
        elif isinstance(v, dict):
            parts.append(_flatten_to_text(v))
        elif isinstance(v, list):
            parts.extend(str(i) for i in v)
    return " ".join(parts).lower()


def _get_field(metadata: dict[str, Any], *candidates: str) -> str | None:
    """Return the first non-empty value from a list of candidate keys."""
    for key in candidates:
        val = metadata.get(key)
        if val and str(val).strip():
            return str(val).strip()
    return None


# ---------------------------------------------------------------------------
# Analysis sub-routines
# ---------------------------------------------------------------------------


def _analyse_device_metadata(
    metadata: dict[str, Any], text: str, state: _AnalysisState
) -> None:
    """Detect legitimate consumer device / OS signatures."""
    detected_labels: list[str] = []
    for keyword, label in DEVICE_SIGNATURES:
        if keyword in text:
            detected_labels.append(label)

    # Also check structured EXIF fields explicitly
    make = _get_field(
        metadata,
        "EXIF:Make", "IFD0:Make", "File:Make", "Composite:Make",
    )
    model = _get_field(
        metadata,
        "EXIF:Model", "IFD0:Model", "File:Model", "Composite:Model",
    )

    if make:
        state.camera_make = make
        state.metadata_richness += 1
    if model:
        state.camera_model = model
        state.metadata_richness += 1

    if detected_labels or make or model:
        state.real_device_metadata_detected = True
        label_str = ", ".join(dict.fromkeys(detected_labels)) if detected_labels else (make or "")
        device_str = f"{make or ''} {model or ''}".strip() or label_str
        state.device = device_str or None
        state.add_finding(
            type_="device_metadata",
            severity="info",
            message=f"Genuine device metadata detected: {device_str or 'unknown device'}.",
        )
        state.risk_delta -= 0.25
        state.confidence_delta += 0.15
    else:
        state.add_finding(
            type_="device_metadata_absent",
            severity="low",
            message="No recognisable device metadata found.",
        )
        state.risk_delta += 0.05


def _analyse_ai_metadata(text: str, state: _AnalysisState) -> None:
    """Detect AI image-generation tool signatures in metadata."""
    hits: list[str] = []
    for sig in AI_SIGNATURES:
        if sig in text:
            hits.append(sig)

    if hits:
        state.ai_metadata_detected = True
        hit_labels = list(dict.fromkeys(hits))[:5]  # de-dup, cap display
        state.add_finding(
            type_="ai_metadata",
            severity="critical",
            message=f"AI generation metadata detected: {', '.join(hit_labels)}.",
        )
        state.risk_delta += 0.55
        state.confidence_delta += 0.25


def _analyse_editing_software(
    metadata: dict[str, Any], text: str, state: _AnalysisState
) -> None:
    """Detect image-editing software signatures."""
    software_field = _get_field(
        metadata,
        "EXIF:Software",
        "IFD0:Software",
        "XMP:CreatorTool",
        "XMP-xmp:CreatorTool",
        "File:Software",
    )
    if software_field:
        state.software = software_field
        state.metadata_richness += 1

    hits: list[str] = []
    search_text = text
    if software_field:
        search_text = search_text + " " + software_field.lower()

    for keyword, label in EDITING_SIGNATURES:
        if keyword in search_text:
            hits.append(label)

    if hits:
        state.editing_software_detected = True
        hit_labels = list(dict.fromkeys(hits))[:5]
        state.add_finding(
            type_="editing_software",
            severity="high",
            message=f"Image editing software detected: {', '.join(hit_labels)}.",
        )
        state.risk_delta += 0.30
        state.confidence_delta += 0.10
    elif software_field:
        state.add_finding(
            type_="software_info",
            severity="info",
            message=f"Software metadata present: {software_field}.",
        )
        state.metadata_richness += 1


def _parse_exif_datetime(dt_str: str) -> datetime | None:
    """Parse common EXIF datetime formats."""
    formats = [
        "%Y:%m:%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y:%m:%d %H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(dt_str[:19], fmt[:len(dt_str[:19])])
        except ValueError:
            continue
    return None


def _analyse_metadata_integrity(
    metadata: dict[str, Any], state: _AnalysisState
) -> None:
    """Perform consistency and integrity checks on metadata."""

    # ── ICC profile ────────────────────────────────────────────────────────
    icc_keys = [k for k in metadata if "icc" in k.lower()]
    if not icc_keys:
        state.add_finding(
            type_="icc_profile_missing",
            severity="low",
            message="ICC profile is missing.",
        )
        state.risk_delta += 0.05
    else:
        state.metadata_richness += 1

    # ── Timestamp analysis ─────────────────────────────────────────────────
    ts_fields = {
        "DateTimeOriginal": _get_field(
            metadata,
            "EXIF:DateTimeOriginal",
            "ExifIFD:DateTimeOriginal",
        ),
        "DateTime": _get_field(
            metadata,
            "EXIF:DateTime",
            "IFD0:ModifyDate",
        ),
        "ModifyDate": _get_field(
            metadata,
            "EXIF:ModifyDate",
            "IFD0:ModifyDate",
            "File:FileModifyDate",
        ),
    }

    parsed: dict[str, datetime] = {}
    for name, val in ts_fields.items():
        if val:
            dt = _parse_exif_datetime(val)
            if dt:
                parsed[name] = dt
            else:
                state.add_finding(
                    type_="invalid_timestamp",
                    severity="medium",
                    message=f"Invalid timestamp format in field {name}: {val!r}.",
                )
                state.risk_delta += 0.10

    if parsed:
        state.metadata_richness += len(parsed)

        # ModifyDate must not be before DateTimeOriginal
        orig = parsed.get("DateTimeOriginal")
        mod = parsed.get("ModifyDate")
        if orig and mod and mod < orig:
            state.add_finding(
                type_="conflicting_timestamps",
                severity="high",
                message=(
                    f"ModifyDate ({mod.date()}) is earlier than DateTimeOriginal "
                    f"({orig.date()}) — impossible ordering."
                ),
            )
            state.risk_delta += 0.20
        elif len(parsed) >= 2:
            state.add_finding(
                type_="consistent_timestamps",
                severity="info",
                message="Timestamps are internally consistent.",
            )
            state.confidence_delta += 0.10

        # Sanity: dates must not be in the future
        now = datetime.utcnow()
        for name, dt in parsed.items():
            if dt > now:
                state.add_finding(
                    type_="future_timestamp",
                    severity="high",
                    message=f"Timestamp {name} is set in the future ({dt.date()}).",
                )
                state.risk_delta += 0.15

    # ── Missing critical metadata ──────────────────────────────────────────
    has_any_exif = any("EXIF" in k or "exif" in k.lower() for k in metadata)
    if not has_any_exif:
        state.add_finding(
            type_="exif_missing",
            severity="medium",
            message="No EXIF data found in image.",
        )
        state.risk_delta += 0.10

    has_any_xmp = any("XMP" in k or "xmp" in k.lower() for k in metadata)
    has_any_iptc = any("IPTC" in k or "iptc" in k.lower() for k in metadata)

    if not has_any_xmp and not has_any_iptc:
        state.add_finding(
            type_="metadata_sections_absent",
            severity="low",
            message="Neither XMP nor IPTC metadata sections are present.",
        )

    # ── Duplicate field detection ──────────────────────────────────────────
    seen_values: dict[str, list[str]] = {}
    for k, v in metadata.items():
        if isinstance(v, str) and v.strip():
            seen_values.setdefault(v.strip(), []).append(k)
    dupes = {v: ks for v, ks in seen_values.items() if len(ks) > 3}
    if dupes:
        state.add_finding(
            type_="duplicate_metadata",
            severity="low",
            message=(
                f"Suspicious duplicate metadata values across {len(dupes)} "
                "distinct fields — possible metadata templating."
            ),
        )
        state.risk_delta += 0.05

    # ── Overall metadata richness check ───────────────────────────────────
    total_fields = len([v for v in metadata.values() if v not in (None, "", {})])
    if total_fields < 5:
        state.add_finding(
            type_="metadata_sparse",
            severity="medium",
            message=f"Metadata is very sparse ({total_fields} meaningful fields).",
        )
        state.risk_delta += 0.10
        state.confidence_delta -= 0.20
    elif total_fields > 30:
        state.confidence_delta += 0.15


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------

_BASE_RISK = 0.30  # neutral starting point


def _compute_risk_score(state: _AnalysisState) -> float:
    score = _BASE_RISK + state.risk_delta
    return max(0.0, min(1.0, round(score, 4)))


def _compute_confidence(state: _AnalysisState, metadata: dict[str, Any]) -> float:
    base = 0.50
    richness_bonus = min(0.20, state.metadata_richness * 0.02)
    conf = base + richness_bonus + state.confidence_delta
    return max(0.05, min(1.0, round(conf, 4)))


def _determine_verdict(risk_score: float) -> str:
    if risk_score < 0.35:
        return "likely_real"
    if risk_score < 0.65:
        return "inconclusive"
    return "suspicious"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def inspect_metadata(image_path: str) -> LayerResult:
    """
    Perform forensic metadata analysis on an uploaded image.

    Parameters
    ----------
    image_path:
        Absolute or relative path to the image file.

    Returns
    -------
    LayerResult
        Fully populated layer result containing verdict, risk score,
        confidence, findings, warnings, and structured evidence.
    """
    state = _AnalysisState()

    # ── 1. Validate file exists ────────────────────────────────────────────
    if not os.path.isfile(image_path):
        state.add_warning(f"File not found: {image_path!r}")
        return LayerResult(
            layer_name="metadata_inspection",
            verdict="inconclusive",
            risk_score=0.5,
            confidence=0.0,
            findings=[
                Finding(
                    type="file_not_found",
                    severity="critical",
                    message=f"Image file does not exist: {image_path!r}",
                )
            ],
            warnings=state.warnings,
            evidence={
                "metadata_present": False,
                "real_device_metadata_detected": False,
                "ai_metadata_detected": False,
                "editing_software_detected": False,
                "software": None,
                "device": None,
                "camera_make": None,
                "camera_model": None,
                "raw_metadata": {},
            },
        )

    # ── 2. Extract metadata ────────────────────────────────────────────────
    try:
        raw_metadata = _extract_metadata(image_path, state)
    except Exception as exc:
        state.add_warning(f"Unexpected metadata extraction failure: {exc}")
        raw_metadata = {}

    state.raw_metadata = raw_metadata
    state.metadata_present = bool(raw_metadata)

    # ── 3. Build searchable text blob ──────────────────────────────────────
    try:
        text_blob = _flatten_to_text(raw_metadata)
    except Exception as exc:
        state.add_warning(f"Failed to flatten metadata for analysis: {exc}")
        text_blob = ""

    # ── 4. Run analysis sub-routines ───────────────────────────────────────
    _safe_call(_analyse_device_metadata, state, metadata=raw_metadata, text=text_blob)
    _safe_call(_analyse_ai_metadata, state, text=text_blob)
    _safe_call(_analyse_editing_software, state, metadata=raw_metadata, text=text_blob)
    _safe_call(_analyse_metadata_integrity, state, metadata=raw_metadata)

    # ── 5. Compute scores and verdict ──────────────────────────────────────
    risk_score = _compute_risk_score(state)
    confidence = _compute_confidence(state, raw_metadata)
    verdict = _determine_verdict(risk_score)

    # ── 6. Assemble evidence dictionary ───────────────────────────────────
    evidence: dict[str, Any] = {
        "metadata_present": state.metadata_present,
        "real_device_metadata_detected": state.real_device_metadata_detected,
        "ai_metadata_detected": state.ai_metadata_detected,
        "editing_software_detected": state.editing_software_detected,
        "software": state.software,
        "device": state.device,
        "camera_make": state.camera_make,
        "camera_model": state.camera_model,
        "raw_metadata": raw_metadata,
    }

    return LayerResult(
        layer_name="metadata_inspection",
        verdict=verdict,
        risk_score=risk_score,
        confidence=confidence,
        findings=state.findings,
        warnings=state.warnings,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Internal: safe dispatcher (prevents analysis crashes)
# ---------------------------------------------------------------------------


def _safe_call(
    fn,
    state: _AnalysisState,
    **kwargs: Any,
) -> None:
    """Call an analysis function; on exception add a warning and continue."""
    try:
        fn(**kwargs, state=state)
    except Exception as exc:
        state.add_warning(
            f"Analysis step '{fn.__name__}' raised an unexpected error: {exc}"
        )
