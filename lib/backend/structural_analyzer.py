from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import os
import cv2
import numpy as np

# Standardized schema dataclasses (shared across forensic layers)
@dataclass
class Finding:
    type: str
    severity: str  # 'low' | 'medium' | 'high' | 'critical'
    message: str

@dataclass
class LayerResult:
    layer_name: str
    verdict: str  # 'likely_real' | 'suspicious' | 'inconclusive'
    risk_score: float
    confidence: float
    findings: List[Finding]
    warnings: List[str]
    evidence: Dict[str, Any]


class _State:
    def __init__(self):
        self.findings: List[Finding] = []
        self.warnings: List[str] = []
        self.risk_delta: float = 0.0
        self.confidence_delta: float = 0.0
        self.misaligned_elements: int = 0
        self.overlapping_boxes: int = 0
        self.font_size_anomalies: int = 0

    def add_finding(self, type_: str, severity: str, message: str):
        self.findings.append(Finding(type=type_, severity=severity, message=message))

    def warn(self, message: str):
        self.warnings.append(message)


def _check_aspect_ratio_and_resolution(img: np.ndarray, state: _State) -> Dict[str, Any]:
    height, width = img.shape[:2]
    aspect_ratio = round(width / height, 3) if height > 0 else 0.0

    # Common mobile aspect ratios (~16:9, ~19.5:9, ~20:9)
    # Extremely unusual ratios often indicate cropped edits or web element grabs
    if aspect_ratio < 0.3 or aspect_ratio > 2.5:
        state.add_finding(
            type_="irregular_aspect_ratio",
            severity="medium",
            message=f"Image aspect ratio ({aspect_ratio}) deviates significantly from standard device screen bounds.",
        )
        state.risk_delta += 0.20
    
    # Ultra-low resolution check
    if width < 300 or height < 300:
        state.add_finding(
            type_="low_resolution",
            severity="low",
            message=f"Dimensions ({width}x{height}) are unusually low for modern device screenshots.",
        )
        state.risk_delta += 0.10

    return {"width": width, "height": height, "aspect_ratio": aspect_ratio}


def _audit_bounding_boxes(ocr_boxes: List[Dict[str, Any]], state: _State):
    """
    Evaluates OCR bounding box structures for overlaps, baseline misalignment,
    and anomalous height variances across text lines.
    
    Expected box dict format: {"text": str, "bbox": [x, y, w, h], "confidence": float}
    """
    if not ocr_boxes or len(ocr_boxes) < 2:
        return

    # Sort boxes vertically (by top y coordinate)
    sorted_boxes = sorted(ocr_boxes, key=lambda b: b["bbox"][1])
    
    lines: List[List[Dict[str, Any]]] = []
    current_line: List[Dict[str, Any]] = []

    # Group boxes into horizontal lines (y-tolerance threshold)
    for box in sorted_boxes:
        if not current_line:
            current_line.append(box)
        else:
            prev_y = current_line[0]["bbox"][1]
            curr_y = box["bbox"][1]
            # Threshold relative to average box height
            avg_h = current_line[0]["bbox"][3]
            if abs(curr_y - prev_y) <= (avg_h * 0.4):
                current_line.append(box)
            else:
                lines.append(current_line)
                current_line = [box]
    if current_line:
        lines.append(current_line)

    # 1. Check for overlapping bounding boxes (sign of pasted/layered elements)
    for i in range(len(ocr_boxes)):
        b1 = ocr_boxes[i]["bbox"]
        for j in range(i + 1, len(ocr_boxes)):
            b2 = ocr_boxes[j]["bbox"]
            # Intersection rectangle check
            x_left = max(b1[0], b2[0])
            y_top = max(b1[1], b2[1])
            x_right = min(b1[0] + b1[2], b2[0] + b2[2])
            y_bottom = min(b1[1] + b1[3], b2[1] + b2[3])

            if x_right > x_left and y_bottom > y_top:
                intersection_area = (x_right - x_left) * (y_bottom - y_top)
                min_area = min(b1[2] * b1[3], b2[2] * b2[3])
                if min_area > 0 and (intersection_area / min_area) > 0.3:
                    state.overlapping_boxes += 1

    if state.overlapping_boxes > 0:
        state.add_finding(
            type_="overlapping_text_elements",
            severity="high",
            message=f"Detected {state.overlapping_boxes} overlapping text bounding boxes, indicating pasted text or UI layering artifacts.",
        )
        state.risk_delta += min(0.15 * state.overlapping_boxes, 0.40)

    # 2. Check baseline misalignment within text lines
    for line in lines:
        if len(line) >= 3:
            baselines = [b["bbox"][1] + b["bbox"][3] for b in line]  # y + h
            baseline_variance = np.var(baselines)
            if baseline_variance > 12.0:
                state.misaligned_elements += 1

    if state.misaligned_elements > 0:
        state.add_finding(
            type_="baseline_misalignment",
            severity="medium",
            message=f"Detected baseline vertical misalignment across {state.misaligned_elements} text lines.",
        )
        state.risk_delta += min(0.10 * state.misaligned_elements, 0.30)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def inspect_structural(
    image_path: str, ocr_data: Optional[List[Dict[str, Any]]] = None
) -> LayerResult:
    """
    Perform structural and geometric bounds inspection on an image file.

    Parameters
    ----------
    image_path : str
        Path to the target image on disk.
    ocr_data : Optional[List[Dict[str, Any]]]
        OCR bounding box predictions if pre-computed.

    Returns
    -------
    LayerResult
        Standardised forensic inspection result.
    """
    state = _State()

    if not os.path.isfile(image_path):
        state.warn(f"File not found or unreadable: {image_path}")
        return LayerResult(
            layer_name="structural",
            verdict="inconclusive",
            risk_score=0.5,
            confidence=0.0,
            findings=[
                Finding(
                    type="file_error",
                    severity="critical",
                    message="Image file could not be found or opened.",
                )
            ],
            warnings=state.warnings,
            evidence={"structural_analysis_performed": False},
        )

    img = cv2.imread(image_path)
    if img is None:
        state.warn(f"Failed to decode image with OpenCV: {image_path}")
        return LayerResult(
            layer_name="structural",
            verdict="inconclusive",
            risk_score=0.5,
            confidence=0.0,
            findings=[
                Finding(
                    type="image_decode_error",
                    severity="critical",
                    message="Image file format is corrupted or unsupported.",
                )
            ],
            warnings=state.warnings,
            evidence={"structural_analysis_performed": False},
        )

    # 1. Geometric & Dimension Audit
    dimension_info = _check_aspect_ratio_and_resolution(img, state)

    # 2. OCR Bounding Box Structural Audit
    if ocr_data:
        _audit_bounding_boxes(ocr_data, state)
        state.confidence_delta += 0.20  # Boost confidence when OCR bounds are available
    else:
        state.warn("No OCR bounding box data provided. Structural audit limited to global geometry.")

    # 3. Base scores & bounds calculation
    base_risk = 0.10
    base_confidence = 0.60

    risk_score = max(0.0, min(1.0, base_risk + state.risk_delta))
    confidence = max(0.0, min(1.0, base_confidence + state.confidence_delta))

    # 4. Verdict determination
    if risk_score >= 0.55:
        verdict = "suspicious"
    elif risk_score < 0.25 and ocr_data is not None:
        verdict = "likely_real"
    else:
        verdict = "inconclusive"

    # 5. Evidence payload
    evidence = {
        "dimensions": dimension_info,
        "ocr_boxes_analyzed": len(ocr_data) if ocr_data else 0,
        "overlapping_boxes": state.overlapping_boxes,
        "misaligned_elements": state.misaligned_elements,
    }

    return LayerResult(
        layer_name="structural",
        verdict=verdict,
        risk_score=round(risk_score, 2),
        confidence=round(confidence, 2),
        findings=state.findings,
        warnings=state.warnings,
        evidence=evidence,
    )