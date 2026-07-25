/// Dart models mirroring the Python PipelineResponse schema from
/// lib/backend/models.py — field names match the JSON keys exactly.

class Finding {
  final String type;
  final String severity;
  final String message;

  const Finding({
    required this.type,
    required this.severity,
    required this.message,
  });

  factory Finding.fromJson(Map<String, dynamic> j) => Finding(
        type: j['type'] as String? ?? '',
        severity: j['severity'] as String? ?? 'low',
        message: j['message'] as String? ?? '',
      );
}

class LayerResult {
  final String layer;
  final String status;   // success | warning | error | skipped
  final String verdict;  // authentic | inconclusive | suspicious | rejected
  final double riskScore;
  final double confidence;
  final List<Finding> findings;
  final List<String> warnings;
  final Map<String, dynamic> evidence;

  const LayerResult({
    required this.layer,
    required this.status,
    required this.verdict,
    required this.riskScore,
    required this.confidence,
    required this.findings,
    required this.warnings,
    required this.evidence,
  });

  factory LayerResult.fromJson(Map<String, dynamic> j) => LayerResult(
        layer: j['layer'] as String? ?? '',
        status: j['status'] as String? ?? 'error',
        verdict: j['verdict'] as String? ?? 'inconclusive',
        riskScore: (j['risk_score'] as num? ?? 0.5).toDouble(),
        confidence: (j['confidence'] as num? ?? 0.0).toDouble(),
        findings: (j['findings'] as List<dynamic>? ?? [])
            .map((f) => Finding.fromJson(f as Map<String, dynamic>))
            .toList(),
        warnings: (j['warnings'] as List<dynamic>? ?? [])
            .map((w) => w.toString())
            .toList(),
        evidence: (j['evidence'] as Map<String, dynamic>?) ?? {},
      );
}

class PipelineResponse {
  final String overallVerdict; // authentic | inconclusive | suspicious | rejected
  final double overallRiskScore;
  final double overallConfidence;
  final String summary;
  final bool circuitBreakerTriggered;
  final Map<String, LayerResult> layerResults;

  const PipelineResponse({
    required this.overallVerdict,
    required this.overallRiskScore,
    required this.overallConfidence,
    required this.summary,
    required this.circuitBreakerTriggered,
    required this.layerResults,
  });

  factory PipelineResponse.fromJson(Map<String, dynamic> j) => PipelineResponse(
        overallVerdict: j['overall_verdict'] as String? ?? 'inconclusive',
        overallRiskScore: (j['overall_risk_score'] as num? ?? 0.5).toDouble(),
        overallConfidence: (j['overall_confidence'] as num? ?? 0.0).toDouble(),
        summary: j['summary'] as String? ?? '',
        circuitBreakerTriggered:
            j['circuit_breaker_triggered'] as bool? ?? false,
        layerResults: (j['layer_results'] as Map<String, dynamic>? ?? {}).map(
          (k, v) => MapEntry(
            k,
            LayerResult.fromJson(v as Map<String, dynamic>),
          ),
        ),
      );

  bool get isSuspicious =>
      overallVerdict == 'suspicious' || overallVerdict == 'rejected';

  bool get isAuthentic => overallVerdict == 'authentic';
}
