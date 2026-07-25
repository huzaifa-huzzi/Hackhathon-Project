from dataclasses import dataclass, field
from typing import Any, Dict, List
import io
import os
import cv2
import numpy as np
from PIL import Image, ImageChops

# Standardized schema dataclasses
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
        self.ela_max_diff: float = 0.0
        self.ela_mean_diff: float = 0.0
        self.fft_high_freq_ratio: float = 0.0
        self.noise_grid_variance: float = 0.0

    def add_finding(self, type_: str, severity: str, message: str):
        self.findings.append(Finding(type=type_, severity=severity, message=message))

    def warn(self, message: str):
        self.warnings.append(message)


def _perform_ela(image_path: str, state: _State, quality: int = 90) -> float:
    """
    Error Level Analysis (ELA): Re-saves image at fixed JPEG quality 
    and checks pixel error distribution for localized compression differences.
    """
    try:
        original = Image.open(image_path).convert("RGB")
        
        # Save to memory buffer at target quality
        buffer = io.BytesIO()
        original.save(buffer, format="JPEG", quality=quality)
        buffer.seek(0)
        resaved = Image.open(buffer)

        # Compute absolute difference
        ela_img = ImageChops.difference(original, resaved)
        extrema = ela_img.getextrema()
        
        # Calculate maximum luminance difference across channels
        max_diff = max([ex[1] for ex in extrema])
        
        # Convert to numpy array for mean analysis
        ela_np = np.array(ela_img, dtype=np.float32)
        mean_diff = np.mean(ela_np)

        state.ela_max_diff = float(max_diff)
        state.ela_mean_diff = float(mean_diff)

        # High variance between max error and mean error highlights localized edits
        if max_diff > 60 and (max_diff / (mean_diff + 1e-5)) > 8.0:
            state.add_finding(
                type_="ela_compression_anomaly",
                severity="high",
                message=f"Error Level Analysis detected localized compression discrepancies (max diff: {max_diff:.1f}, mean: {mean_diff:.1f}).",
            )
            state.risk_delta += 0.30
        
        return mean_diff
    except Exception as e:
        state.warn(f"ELA computation failed: {str(e)}")
        return 0.0


def _perform_fft_analysis(img_gray: np.ndarray, state: _State):
    """
    Fast Fourier Transform (FFT) analysis to detect unnatural periodic patterns,
    resampling grids, or AI generation high-frequency falloff artifacts.
    """
    try:
        h, w = img_gray.shape
        # Compute 2D DFT and shift zero frequency component to center
        dft = np.fft.fft2(img_gray.astype(np.float32))
        fshift = np.fft.fftshift(dft)
        magnitude_spectrum = 20 * np.log(np.abs(fshift) + 1e-5)

        # Radius for high frequency ring
        center_y, center_x = h // 2, w // 2
        y_grid, x_grid = np.ogrid[:h, :w]
        dist_from_center = np.sqrt((x_grid - center_x) ** 2 + (y_grid - center_y) ** 2)

        max_radius = min(center_x, center_y)
        if max_radius == 0:
            return

        high_freq_mask = dist_from_center > (max_radius * 0.7)
        total_energy = np.sum(magnitude_spectrum)
        high_freq_energy = np.sum(magnitude_spectrum[high_freq_mask])

        ratio = (high_freq_energy / (total_energy + 1e-5))
        state.fft_high_freq_ratio = float(round(ratio, 4))

        # AI generated or heavily resampled/smoothed images often show severe high-frequency attenuation
        if ratio < 0.08:
            state.add_finding(
                type_="fft_synthetic_blur_artifact",
                severity="medium",
                message=f"FFT frequency spectrum exhibits anomalous high-frequency attenuation (ratio: {ratio:.4f}), typical of AI synthesis or synthetic rendering.",
            )
            state.risk_delta += 0.25
    except Exception as e:
        state.warn(f"FFT analysis failed: {str(e)}")


def _perform_noise_grid_analysis(img_gray: np.ndarray, state: _State):
    """
    Divides image into a 4x4 grid and measures Laplacian noise variance across regions.
    Spliced or inserted elements display distinct local noise profiles.
    """
    try:
        h, w = img_gray.shape
        grid_h, grid_w = h // 4, w // 4
        
        if grid_h < 10 or grid_w < 10:
            return

        variances = []
        for r in range(4):
            for c in range(4):
                cell = img_gray[r * grid_h : (r + 1) * grid_h, c * grid_w : (c + 1) * grid_w]
                laplacian_var = cv2.Laplacian(cell, cv2.CV_64F).var()
                variances.append(laplacian_var)

        std_var = float(np.std(variances))
        mean_var = float(np.mean(variances))
        coeff_of_variation = std_var / (mean_var + 1e-5)

        state.noise_grid_variance = round(coeff_of_variation, 4)

        if coeff_of_variation > 1.8:
            state.add_finding(
                type_="inconsistent_noise_distribution",
                severity="high",
                message=f"Inconsistent noise pattern across image grid (coefficient of variation: {coeff_of_variation:.2f}), suggesting localized manipulation or splicing.",
            )
            state.risk_delta += 0.30
    except Exception as e:
        state.warn(f"Noise grid analysis failed: {str(e)}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def inspect_pixel_signals(image_path: str) -> LayerResult:
    """
    Perform pixel and signal-level forensic inspection on an image file.

    Parameters
    ----------
    image_path : str
        Path to the target image on disk.

    Returns
    -------
    LayerResult
        Standardised forensic inspection result.
    """
    state = _State()

    if not os.path.isfile(image_path):
        state.warn(f"File not found or unreadable: {image_path}")
        return LayerResult(
            layer_name="pixel_signal",
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
            evidence={"pixel_analysis_performed": False},
        )

    img_gray = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img_gray is None:
        state.warn(f"Failed to decode image with OpenCV: {image_path}")
        return LayerResult(
            layer_name="pixel_signal",
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
            evidence={"pixel_analysis_performed": False},
        )

    # 1. Error Level Analysis (ELA)
    _perform_ela(image_path, state)

    # 2. FFT Spectrum Analysis
    _perform_fft_analysis(img_gray, state)

    # 3. Local Noise Variance Grid Analysis
    _perform_noise_grid_analysis(img_gray, state)

    # 4. Base scores & bounds calculation
    base_risk = 0.10
    base_confidence = 0.70  # Pixel signals provide solid empirical metrics

    risk_score = max(0.0, min(1.0, base_risk + state.risk_delta))
    confidence = max(0.0, min(1.0, base_confidence + state.confidence_delta))

    # 5. Verdict determination
    if risk_score >= 0.55:
        verdict = "suspicious"
    elif risk_score < 0.25:
        verdict = "likely_real"
    else:
        verdict = "inconclusive"

    # 6. Evidence payload
    evidence = {
        "ela_max_diff": state.ela_max_diff,
        "ela_mean_diff": state.ela_mean_diff,
        "fft_high_freq_ratio": state.fft_high_freq_ratio,
        "noise_grid_variance": state.noise_grid_variance,
    }

    return LayerResult(
        layer_name="pixel_signal",
        verdict=verdict,
        risk_score=round(risk_score, 2),
        confidence=round(confidence, 2),
        findings=state.findings,
        warnings=state.warnings,
        evidence=evidence,
    )