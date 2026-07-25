import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../models/pipeline_response.dart';

/// Base URL of the SikkaCheck FastAPI backend.
///
/// For local development, the backend runs on port 8000.
/// Change this to your deployed URL before releasing to production.
const String kBaseUrl = 'http://127.0.0.1:8000';

class ForensicApiException implements Exception {
  final int? statusCode;
  final String message;

  const ForensicApiException(this.message, {this.statusCode});

  @override
  String toString() => statusCode != null
      ? 'ForensicApiException($statusCode): $message'
      : 'ForensicApiException: $message';
}

class ForensicApi {
  ForensicApi._();

  /// Upload [imageBytes] with the given [filename] to POST /api/v1/analyze
  /// and return the parsed [PipelineResponse].
  ///
  /// [ocrData] is optional — pass pre-computed OCR bounding boxes if available.
  static Future<PipelineResponse> analyze({
    required Uint8List imageBytes,
    required String filename,
    List<Map<String, dynamic>>? ocrData,
  }) async {
    final uri = Uri.parse('$kBaseUrl/api/v1/analyze');

    final request = http.MultipartRequest('POST', uri)
      ..files.add(
        http.MultipartFile.fromBytes(
          'file',
          imageBytes,
          filename: filename,
        ),
      );

    if (ocrData != null) {
      request.fields['ocr_data'] = jsonEncode(ocrData);
    }

    final http.StreamedResponse streamed;
    try {
      streamed = await request.send().timeout(
        const Duration(seconds: 60),
        onTimeout: () => throw const ForensicApiException(
          'Request timed out after 60 seconds.',
        ),
      );
    } catch (e) {
      if (e is ForensicApiException) rethrow;
      throw ForensicApiException('Network error: $e');
    }

    final body = await streamed.stream.bytesToString();

    if (streamed.statusCode == 200) {
      try {
        final json = jsonDecode(body) as Map<String, dynamic>;
        return PipelineResponse.fromJson(json);
      } catch (e) {
        throw ForensicApiException('Failed to parse server response: $e');
      }
    }

    // Non-200 response — extract detail from FastAPI error body
    String detail = 'Unknown server error';
    try {
      final err = jsonDecode(body) as Map<String, dynamic>;
      detail = err['detail']?.toString() ?? detail;
    } catch (_) {}

    throw ForensicApiException(detail, statusCode: streamed.statusCode);
  }

  /// Quick health check — returns true if the backend is reachable.
  static Future<bool> isHealthy() async {
    try {
      final res = await http
          .get(Uri.parse('$kBaseUrl/health'))
          .timeout(const Duration(seconds: 5));
      return res.statusCode == 200;
    } catch (_) {
      return false;
    }
  }
}
