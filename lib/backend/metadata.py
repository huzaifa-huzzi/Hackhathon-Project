"""
lib/backend/metadata.py
=======================
SikkaCheck — Metadata Inspection Layer

Performs forensic metadata analysis on an uploaded image and returns a
standardised LayerResult.

Rules enforced by this module:
  - Metadata only — no pixel inspection, no OCR, no ML models.
  - ExifTool is the primary extractor; Pillow + exifread are the fallback.
  - Never crashes on malformed metadata; all errors become warnings.
"""

from __future__ import annotations

import json
import mimetypes
import os
import subprocess
import warnings as _warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Optional imports — graceful degradation when packages are absent
# ---------------------------------------------------------------------------

try:
    from PIL import Image as _PilImage
    from PIL.ExifTags import TAGS as _PIL_TAGS

    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False
    _PIL_TAGS = {}

try:
    import exifread as _exifread

    _EXIFREAD_AVAILABLE = True
except ImportError:
    _EXIFREAD_AVAILABLE = False


# ---------------------------------------------------------------------------
# Output schema (Pydantic)
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single structured forensic observation."""

    type: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    message: str


class LayerResult(BaseModel):
    """Standardised result produced by every SikkaCheck forensic layer."""

    layer_name: str
    verdict: str          # "likely_real" | "inconclusive" | "suspicious"
    risk_score: float     # 0.0 – 1.0
    confidence: float     # 0.0 – 1.0
    findings: list[Finding]
    warnings: list[str]
    evidence: dict[str, Any]


# ---------------------------------------------------------------------------
# Configuration — extend these lists without touching analysis logic
# ---------------------------------------------------------------------------

#: Signatures that indicate an AI image-generation tool.
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
    "adobe firefly",
    "firefly",
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
    "generative fill",
    "ai generated",
    "diffusion",
    # Prompt/parameter artifacts left in metadata
    "cfg scale",
    "sampling steps",
    "seed:",
    "negative prompt",
]

#: Real consumer device / OS signatures: (search_keyword, canonical_label).
DEVICE_SIGNATURES: list[tuple[str, str]] = [
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

#: Image-editing software signatures: (search_keyword, canonical_label).
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
    ("corel", "Corel"),
    ("paint shop pro", "Paint Shop Pro"),
    ("inkscape", "Inkscape"),
]


# ---------------------------------------------------------------------------
# Internal accumulator (not exposed outside this module)
# ---------------------------------------------------------------------------


@dataclass
class _State:
    """Mutable accumulator used throughout the analysis pipeline."""

    raw_metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Score deltas — accumulated by each analysis step
    risk_delta: float = 0.0
    confidence_delta: float = 0.0
    metadata_richness: int = 0   # count of meaningful metadata fields found

    # Evidence values
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

    def warn(self, message: str) -> None:
        self.warnings.append(message)


# ---------------------------------------------------------------------------
# Metadata extraction helpers
# ---------------------------------------------------------------------------


def _run_exiftool(image_path: str) -> dict[str, Any] | None:
    """
    Run ExifTool and return its JSON output as a dict.

    Returns None if ExifTool is not installed or the call fails.
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
        pass  # ExifTool not installed
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
        _warnings.warn(f"ExifTool error: {exc}")
    return None


def _extract_via_pillow(image_path: str, state: _State) -> dict[str, Any]:
    """Extract metadata with Pillow."""
    meta: dict[str, Any] = {}
    if not _PIL_AVAILABLE:
        state.warn("Pillow is not installed; skipping Pillow extraction.")
        return meta
    try:
        with _PilImage.open(image_path) as img:
            meta["File:ImageWidth"] = img.width
            meta["File:ImageHeight"] = img.height
            meta["File:ColorMode"] = img.mode

            info = img.info or {}
            dpi = info.get("dpi")
            if dpi:
                meta["File:XResolution"] = dpi[0]
                meta["File:YResolution"] = dpi[1]

            if info.get("icc_profile"):
                meta["ICC_Profile:Present"] = True

            # EXIF via Pillow
            exif_data = img._getexif() if hasattr(img, "_getexif") else None  # type: ignore[attr-defined]
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = _PIL_TAGS.get(tag_id, str(tag_id))
                    meta[f"EXIF:{tag_name}"] = (
                        str(value)
                        if not isinstance(value, (str, int, float))
                        else value
                    )

            for k, v in info.items():
                if k not in ("dpi", "icc_profile", "exif") and isinstance(v, str):
                    meta[f"File:Info:{k}"] = v
    except Exception as exc:
        state.warn(f"Pillow extraction error: {exc}")
    return meta


def _extract_via_exifread(image_path: str, state: _State) -> dict[str, Any]:
    """Extract EXIF metadata with exifread."""
    meta: dict[str, Any] = {}
    if not _EXIFREAD_AVAILABLE:
        state.warn("exifread is not installed; skipping exifread extraction.")
        return meta
    try:
        with open(image_path, "rb") as fh:
            tags = _exifread.process_file(fh, details=True)
        for tag, value in tags.items():
            meta[f"EXIF:{tag}"] = str(value)
    except Exception as exc:
        state.warn(f"exifread extraction error: {exc}")
    return meta


def _extract_file_info(image_path: str, state: _State) -> dict[str, Any]:
    """Collect file-system level metadata (always available)."""
    meta: dict[str, Any] = {}
    try:
        stat = os.stat(image_path)
        meta["File:FileSize"] = stat.st_size
        meta["File:FileName"] = os.path.basename(image_path)
        _, ext = os.path.splitext(image_path)
        meta["File:FileExtension"] = ext.lstrip(".").lower()
        mime, _ = mimetypes.guess_type(image_path)
        if mime:
            meta["File:MIMEType"] = mime
    except Exception as exc:
        state.warn(f"File info extraction error: {exc}")
    return meta


def _extract_metadata(image_path: str, state: _State) -> dict[str, Any]:
    """
    Full extraction pipeline: ExifTool → Pillow + exifread → file info.

    ExifTool output is preferred; the other sources supplement or replace it
    when ExifTool is unavailable.
    """
    combined: dict[str, Any] = {}
    combined.update(_extract_file_info(image_path, state))

    exiftool_result = _run_exiftool(image_path)
    if exiftool_result:
        for group, fields in exiftool_result.items():
            if isinstance(fields, dict):
                for k, v in fields.items():
                    combined[f"{group}:{k}"] = v
            else:
                combined[group] = fields
    else:
        state.warn(
            "ExifTool unavailable or returned no output; "
            "using Pillow + exifread fallback."
        )
        combined.update(_extract_via_pillow(image_path, state))
        combined.update(_extract_via_exifread(image_path, state))

    return combined


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------


def _flatten_to_text(metadata: dict[str, Any]) -> str:
    """Produce a single lowercase string from all metadata values."""
    parts: list[str] = []

    def _walk(obj: Any) -> None:
        if isinstance(obj, str):
            parts.append(obj)
        elif isinstance(obj, (int, float)):
            parts.append(str(obj))
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item)

    _walk(metadata)
    return " ".join(parts).lower()


def _get_field(metadata: dict[str, Any], *candidates: str) -> str | None:
    """Return the first non-empty string value from a list of candidate keys."""
    for key in candidates:
        val = metadata.get(key)
        if val and str(val).strip():
            return str(val).strip()
    return None


def _parse_exif_datetime(dt_str: str) -> datetime | None:
    """Parse common EXIF datetime string formats."""
    for fmt in (
        "%Y:%m:%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y:%m:%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(dt_str[:19], fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Analysis sub-routines
# ---------------------------------------------------------------------------


def _analyse_device_metadata(
    metadata: dict[str, Any], text: str, state: _State
) -> None:
    """Detect legitimate consumer device / OS signatures in metadata."""
    detected_labels: list[str] = []
    for keyword, label in DEVICE_SIGNATURES:
        if keyword in text:
            detected_labels.append(label)

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
        device_str = (
            f"{make or ''} {model or ''}".strip()
            or ", ".join(dict.fromkeys(detected_labels))
        )
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
            severity="medium",
            message="No recognisable device metadata found.",
        )
        state.risk_delta += 0.10


def _analyse_ai_metadata(text: str, state: _State) -> None:
    """Detect AI image-generation tool signatures in flattened metadata."""
    hits: list[str] = [sig for sig in AI_SIGNATURES if sig in text]
    if hits:
        state.ai_metadata_detected = True
        display = list(dict.fromkeys(hits))[:5]
        state.add_finding(
            type_="ai_metadata",
            severity="critical",
            message=f"AI generation metadata detected: {', '.join(display)}.",
        )
        state.risk_delta += 0.55
        state.confidence_delta += 0.25


def _analyse_editing_software(
    metadata: dict[str, Any], text: str, state: _State
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

    search_text = text + (" " + software_field.lower() if software_field else "")
    hits: list[str] = [label for kw, label in EDITING_SIGNATURES if kw in search_text]

    if hits:
        state.editing_software_detected = True
        display = list(dict.fromkeys(hits))[:5]
        state.add_finding(
            type_="editing_software",
            severity="high",
            message=f"Image editing software detected: {', '.join(display)}.",
        )
        state.risk_delta += 0.30
        state.confidence_delta += 0.10
    elif software_field:
        state.add_finding(
            type_="software_info",
            severity="info",
            message=f"Software metadata present: {software_field}.",
        )


def _analyse_metadata_integrity(
    metadata: dict[str, Any], state: _State
) -> None:
    """Perform consistency and integrity checks."""

    # ── ICC profile ────────────────────────────────────────────────────────
    if any("icc" in k.lower() for k in metadata):
        state.metadata_richness += 1
    else:
        state.add_finding(
            type_="icc_profile_missing",
            severity="medium",
            message="ICC colour profile is missing. Genuine device screenshots include an ICC profile.",
        )
        state.risk_delta += 0.10

    # ── Timestamp analysis ─────────────────────────────────────────────────
    ts_map = {
        "DateTimeOriginal": _get_field(
            metadata, "EXIF:DateTimeOriginal", "ExifIFD:DateTimeOriginal"
        ),
        "DateTime": _get_field(
            metadata, "EXIF:DateTime", "IFD0:DateTime"
        ),
        "ModifyDate": _get_field(
            metadata, "EXIF:ModifyDate", "IFD0:ModifyDate", "File:FileModifyDate"
        ),
    }

    parsed: dict[str, datetime] = {}
    for name, val in ts_map.items():
        if not val:
            continue
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
        now = datetime.utcnow()

        # Timestamps must not be in the future
        for name, dt in parsed.items():
            if dt > now:
                state.add_finding(
                    type_="future_timestamp",
                    severity="high",
                    message=f"Timestamp {name} is set in the future ({dt.date()}).",
                )
                state.risk_delta += 0.15

        # ModifyDate must not pre-date DateTimeOriginal
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

    # ── EXIF / XMP / IPTC presence ─────────────────────────────────────────
    has_exif = any("exif" in k.lower() for k in metadata)
    has_xmp = any("xmp" in k.lower() for k in metadata)
    has_iptc = any("iptc" in k.lower() for k in metadata)

    if not has_exif:
        state.add_finding(
            type_="exif_missing",
            severity="medium",
            message="No EXIF data found in image.",
        )
        state.risk_delta += 0.15

    if not has_xmp and not has_iptc:
        state.add_finding(
            type_="metadata_sections_absent",
            severity="low",
            message="Neither XMP nor IPTC metadata sections are present.",
        )

    # ── Metadata sparseness ────────────────────────────────────────────────
    meaningful = len([v for v in metadata.values() if v not in (None, "", {})])
    if meaningful < 5:
        state.add_finding(
            type_="metadata_sparse",
            severity="medium",
            message=f"Metadata is very sparse ({meaningful} meaningful fields).",
        )
        state.risk_delta += 0.10
        state.confidence_delta -= 0.20
    elif meaningful > 30:
        state.confidence_delta += 0.15

    # ── Duplicate values (templated metadata) ──────────────────────────────
    seen: dict[str, list[str]] = {}
    for k, v in metadata.items():
        if isinstance(v, str) and v.strip():
            seen.setdefault(v.strip(), []).append(k)
    dupes = {v: ks for v, ks in seen.items() if len(ks) > 3}
    if dupes:
        state.add_finding(
            type_="duplicate_metadata",
            severity="low",
            message=(
                f"Suspicious duplicate metadata values across {len(dupes)} "
                "distinct field groups — possible metadata templating."
            ),
        )
        state.risk_delta += 0.05


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------

_BASE_RISK = 0.30


def _compute_risk_score(state: _State) -> float:
    return max(0.0, min(1.0, round(_BASE_RISK + state.risk_delta, 4)))


def _compute_confidence(state: _State) -> float:
    richness_bonus = min(0.20, state.metadata_richness * 0.02)
    conf = 0.50 + richness_bonus + state.confidence_delta
    return max(0.05, min(1.0, round(conf, 4)))


def _determine_verdict(risk_score: float) -> str:
    if risk_score < 0.35:
        return "likely_real"
    if risk_score < 0.65:
        return "inconclusive"
    return "suspicious"


# ---------------------------------------------------------------------------
# Safe dispatcher — prevents a single analysis step from crashing the layer
# ---------------------------------------------------------------------------


def _safe_run(fn, state: _State, **kwargs: Any) -> None:
    try:
        fn(**kwargs, state=state)
    except Exception as exc:
        state.warn(f"Analysis step '{fn.__name__}' raised an unexpected error: {exc}")


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
        Fully populated result containing verdict, risk score, confidence,
        findings, warnings, and structured evidence.
    """
    state = _State()

    # ── Guard: file must exist ─────────────────────────────────────────────
    if not os.path.isfile(image_path):
        state.warn(f"File not found: {image_path!r}")
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

    # ── Step 1: Extract metadata ───────────────────────────────────────────
    try:
        raw = _extract_metadata(image_path, state)
    except Exception as exc:
        state.warn(f"Unexpected metadata extraction failure: {exc}")
        raw = {}

    state.raw_metadata = raw
    state.metadata_present = bool(raw)

    # ── Step 2: Build searchable text blob ────────────────────────────────
    try:
        text = _flatten_to_text(raw)
    except Exception as exc:
        state.warn(f"Failed to flatten metadata: {exc}")
        text = ""

    # ── Step 3: Run analysis steps ────────────────────────────────────────
    _safe_run(_analyse_device_metadata, state, metadata=raw, text=text)
    _safe_run(_analyse_ai_metadata, state, text=text)
    _safe_run(_analyse_editing_software, state, metadata=raw, text=text)
    _safe_run(_analyse_metadata_integrity, state, metadata=raw)

    # ── Step 4: Compute scores and verdict ────────────────────────────────
    risk_score = _compute_risk_score(state)
    confidence = _compute_confidence(state)
    verdict = _determine_verdict(risk_score)

    # ── Step 5: Assemble and return ───────────────────────────────────────
    return LayerResult(
        layer_name="metadata_inspection",
        verdict=verdict,
        risk_score=risk_score,
        confidence=confidence,
        findings=state.findings,
        warnings=state.warnings,
        evidence={
            "metadata_present": state.metadata_present,
            "real_device_metadata_detected": state.real_device_metadata_detected,
            "ai_metadata_detected": state.ai_metadata_detected,
            "editing_software_detected": state.editing_software_detected,
            "software": state.software,
            "device": state.device,
            "camera_make": state.camera_make,
            "camera_model": state.camera_model,
            "raw_metadata": raw,
        },
    )
