import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../models/pipeline_response.dart';
import '../services/forensic_api.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Uint8List? _selectedImageBytes;
  String? _fileName;
  bool _isProcessing = false;
  bool _showElaMode = false;

  PipelineResponse? _result;
  String? _errorMessage;

  // ── Image pick + real API call ──────────────────────────────────────────

  Future<void> _pickImage() async {
    FilePickerResult? picked;
    try {
      picked = await FilePicker.platform.pickFiles(
        type: FileType.image,
        withData: true,
      );
    } catch (e) {
      debugPrint('File picker error: $e');
      return;
    }

    if (picked == null || picked.files.single.bytes == null) return;

    final bytes = picked.files.single.bytes!;
    final name = picked.files.single.name;

    setState(() {
      _selectedImageBytes = bytes;
      _fileName = name;
      _isProcessing = true;
      _showElaMode = false;
      _result = null;
      _errorMessage = null;
    });

    try {
      final response = await ForensicApi.analyze(
        imageBytes: bytes,
        filename: name,
      );
      setState(() {
        _result = response;
        _isProcessing = false;
        _showElaMode = response.isSuspicious;
      });
    } on ForensicApiException catch (e) {
      setState(() {
        _errorMessage = e.message;
        _isProcessing = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = 'Unexpected error: $e';
        _isProcessing = false;
      });
    }
  }

  // ── Build ────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _buildAppBar(context),
      body: LayoutBuilder(
        builder: (context, constraints) {
          final isWide = constraints.maxWidth > 900;
          return SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1300),
                child: isWide
                    ? Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Expanded(flex: 5, child: _buildUploadCard()),
                          const SizedBox(width: 20),
                          Expanded(flex: 4, child: _buildReportCard()),
                        ],
                      )
                    : Column(
                        children: [
                          _buildUploadCard(),
                          const SizedBox(height: 20),
                          _buildReportCard(),
                        ],
                      ),
              ),
            ),
          );
        },
      ),
    );
  }

  // ── AppBar ───────────────────────────────────────────────────────────────

  PreferredSizeWidget _buildAppBar(BuildContext context) {
    final isMobile = MediaQuery.of(context).size.width < 600;
    return AppBar(
      backgroundColor: const Color(0xFF161B22),
      elevation: 0,
      titleSpacing: 12,
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF2F81F7), Color(0xFF3FB950)],
              ),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.shield_outlined,
                color: Colors.white, size: 20),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'SikkaCheck',
                  style: GoogleFonts.inter(
                      fontSize: isMobile ? 16 : 18,
                      fontWeight: FontWeight.bold),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  isMobile
                      ? 'Forensics Engine'
                      : 'Payment Screenshot Forensics Engine',
                  style: GoogleFonts.inter(
                      fontSize: 10, color: const Color(0xFF8B949E)),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        Padding(
          padding: const EdgeInsets.only(right: 12),
          child: Container(
            padding: EdgeInsets.symmetric(
                horizontal: isMobile ? 8 : 12, vertical: 6),
            decoration: BoxDecoration(
              color: const Color(0xFF238636).withValues(alpha: 0.15),
              border: Border.all(color: const Color(0xFF238636)),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.circle, size: 7, color: Color(0xFF3FB950)),
                const SizedBox(width: 5),
                Text(
                  isMobile ? 'Live' : 'Live API',
                  style: const TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.w600,
                      color: Color(0xFF3FB950)),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  // ── Upload card ──────────────────────────────────────────────────────────

  Widget _buildUploadCard() {
    return Card(
      color: const Color(0xFF161B22),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: Color(0xFF30363D)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Row(
              children: [
                Icon(Icons.cloud_upload_outlined, color: Color(0xFF2F81F7)),
                SizedBox(width: 8),
                Text('Receipt Screenshot Input',
                    style:
                        TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
              ],
            ),
            const Divider(color: Color(0xFF30363D), height: 24),
            if (_isProcessing)
              _buildProcessingState()
            else if (_selectedImageBytes == null)
              _buildDropZone()
            else
              _buildImagePreview(),
          ],
        ),
      ),
    );
  }

  Widget _buildProcessingState() {
    return Container(
      height: 280,
      alignment: Alignment.center,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const CircularProgressIndicator(color: Color(0xFF2F81F7)),
          const SizedBox(height: 16),
          Text(
            'Running forensic pipeline…',
            style: GoogleFonts.inter(
                color: const Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 4),
          Text(
            'Metadata · Pixel · Structural layers running in parallel',
            style: GoogleFonts.inter(
                color: const Color(0xFF8B949E), fontSize: 11),
          ),
        ],
      ),
    );
  }

  Widget _buildDropZone() {
    return GestureDetector(
      onTap: _pickImage,
      child: Container(
        height: 280,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: const Color(0xFF21262D).withValues(alpha: 0.5),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: const Color(0xFF30363D), width: 2),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.add_photo_alternate_outlined,
                size: 46, color: Color(0xFF2F81F7)),
            const SizedBox(height: 10),
            const Text('Click to Browse Screenshot',
                style:
                    TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
                textAlign: TextAlign.center),
            const SizedBox(height: 4),
            Text('Supports PNG, JPG, WEBP',
                style: TextStyle(fontSize: 11, color: Colors.grey[500])),
            const SizedBox(height: 16),
            Wrap(
              alignment: WrapAlignment.center,
              spacing: 6,
              runSpacing: 6,
              children: [
                _buildTag('JazzCash'),
                _buildTag('EasyPaisa'),
                _buildTag('Raast'),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildImagePreview() {
    return Column(
      children: [
        Container(
          height: 320,
          width: double.infinity,
          decoration: BoxDecoration(
            color: const Color(0xFF0D1117),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: const Color(0xFF30363D)),
          ),
          child: Stack(
            alignment: Alignment.center,
            children: [
              Image.memory(_selectedImageBytes!, fit: BoxFit.contain),
              if (_showElaMode)
                Positioned.fill(
                  child: Container(
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(8),
                      gradient: RadialGradient(
                        colors: [
                          const Color(0xFFF85149).withValues(alpha: 0.55),
                          const Color(0xFF3FB950).withValues(alpha: 0.2),
                          Colors.transparent,
                        ],
                        radius: 0.85,
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  backgroundColor: !_showElaMode
                      ? const Color(0xFF2F81F7)
                      : const Color(0xFF21262D),
                  foregroundColor: Colors.white,
                  side: const BorderSide(color: Color(0xFF30363D)),
                  padding: const EdgeInsets.symmetric(vertical: 10),
                ),
                onPressed: () => setState(() => _showElaMode = false),
                icon: const Icon(Icons.image, size: 16),
                label:
                    const Text('Original', style: TextStyle(fontSize: 12)),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  backgroundColor: _showElaMode
                      ? const Color(0xFF2F81F7)
                      : const Color(0xFF21262D),
                  foregroundColor: Colors.white,
                  side: const BorderSide(color: Color(0xFF30363D)),
                  padding: const EdgeInsets.symmetric(vertical: 10),
                ),
                onPressed: () => setState(() => _showElaMode = true),
                icon: const Icon(Icons.radar, size: 16),
                label:
                    const Text('ELA Mode', style: TextStyle(fontSize: 12)),
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        TextButton.icon(
          onPressed: _pickImage,
          icon: const Icon(Icons.refresh, size: 15),
          label: const Text('Upload Another Image',
              style: TextStyle(fontSize: 12)),
        ),
      ],
    );
  }

  // ── Forensic report card ─────────────────────────────────────────────────

  Widget _buildReportCard() {
    return Card(
      color: const Color(0xFF161B22),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: Color(0xFF30363D)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.memory, color: Color(0xFF2F81F7)),
                SizedBox(width: 8),
                Text('Forensic Analysis Output',
                    style:
                        TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
              ],
            ),
            const Divider(color: Color(0xFF30363D), height: 24),
            _buildVerdictBanner(),
            if (_result != null) ...[
              const SizedBox(height: 16),
              _buildScoreRow(),
              const SizedBox(height: 16),
              _sectionHeader('Layer Results'),
              const SizedBox(height: 8),
              ..._result!.layerResults.entries
                  .map((e) => _buildLayerRow(e.key, e.value)),
              if (_result!.layerResults.values
                  .any((l) => l.findings.isNotEmpty)) ...[
                const SizedBox(height: 16),
                _sectionHeader('Key Findings'),
                const SizedBox(height: 8),
                ..._buildFindings(),
              ],
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildVerdictBanner() {
    // Error state
    if (_errorMessage != null) {
      return _banner(
        color: const Color(0xFFF85149),
        icon: Icons.error_outline,
        text: 'Error: $_errorMessage',
      );
    }

    // No result yet
    if (_result == null) {
      return _banner(
        color: const Color(0xFF8B949E),
        icon: Icons.info_outline,
        text: 'Upload a screenshot to run the forensic pipeline.',
        bordered: false,
      );
    }

    final v = _result!.overallVerdict;
    if (v == 'authentic') {
      return _banner(
        color: const Color(0xFF3FB950),
        icon: Icons.check_circle_outline,
        text: 'AUTHENTIC — Screenshot integrity verified.',
      );
    }
    if (v == 'suspicious' || v == 'rejected') {
      return _banner(
        color: const Color(0xFFF85149),
        icon: Icons.warning_amber_rounded,
        text: v == 'rejected'
            ? 'REJECTED — Circuit breaker triggered. High-confidence forgery.'
            : 'SUSPICIOUS — Forensic anomalies detected.',
      );
    }
    return _banner(
      color: const Color(0xFFD29922),
      icon: Icons.help_outline,
      text: 'INCONCLUSIVE — Insufficient evidence to determine authenticity.',
    );
  }

  Widget _banner({
    required Color color,
    required IconData icon,
    required String text,
    bool bordered = true,
  }) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(8),
        border: bordered ? Border.all(color: color) : null,
      ),
      child: Row(
        children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: TextStyle(
                  color: color, fontWeight: FontWeight.bold, fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScoreRow() {
    final r = _result!;
    return Row(
      children: [
        Expanded(
          child: _metricTile(
            label: 'Risk Score',
            value: '${(r.overallRiskScore * 100).toStringAsFixed(0)}%',
            color: r.overallRiskScore >= 0.65
                ? const Color(0xFFF85149)
                : r.overallRiskScore >= 0.35
                    ? const Color(0xFFD29922)
                    : const Color(0xFF3FB950),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: _metricTile(
            label: 'Confidence',
            value: '${(r.overallConfidence * 100).toStringAsFixed(0)}%',
            color: const Color(0xFF2F81F7),
          ),
        ),
      ],
    );
  }

  Widget _metricTile(
      {required String label,
      required String value,
      required Color color}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: const Color(0xFF21262D),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label,
              style: const TextStyle(
                  fontSize: 10, color: Color(0xFF8B949E))),
          const SizedBox(height: 4),
          Text(value,
              style: GoogleFonts.jetBrainsMono(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: color)),
        ],
      ),
    );
  }

  Widget _buildLayerRow(String name, LayerResult layer) {
    final verdictColor = layer.verdict == 'authentic'
        ? const Color(0xFF3FB950)
        : layer.verdict == 'suspicious' || layer.verdict == 'rejected'
            ? const Color(0xFFF85149)
            : const Color(0xFFD29922);

    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Container(
        padding:
            const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        decoration: BoxDecoration(
          color: const Color(0xFF21262D),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          children: [
            Expanded(
              child: Text(
                name.replaceAll('_', ' '),
                style: const TextStyle(
                    fontSize: 12, color: Color(0xFF8B949E)),
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: verdictColor.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: verdictColor.withValues(alpha: 0.4)),
              ),
              child: Text(
                layer.verdict.toUpperCase(),
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: verdictColor),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              '${(layer.riskScore * 100).toStringAsFixed(0)}%',
              style: GoogleFonts.jetBrainsMono(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  color: verdictColor),
            ),
          ],
        ),
      ),
    );
  }

  List<Widget> _buildFindings() {
    final findings = _result!.layerResults.values
        .expand((l) => l.findings)
        .where((f) =>
            f.severity == 'high' ||
            f.severity == 'critical' ||
            f.severity == 'medium')
        .take(6)
        .toList();

    return findings.map((f) {
      final color = f.severity == 'critical'
          ? const Color(0xFFF85149)
          : f.severity == 'high'
              ? const Color(0xFFD29922)
              : const Color(0xFF8B949E);
      return Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Container(
          padding:
              const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(6),
            border:
                Border.all(color: color.withValues(alpha: 0.3)),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.circle, size: 7, color: color),
              const SizedBox(width: 8),
              Expanded(
                child: Text(f.message,
                    style: TextStyle(fontSize: 11, color: color)),
              ),
            ],
          ),
        ),
      );
    }).toList();
  }

  // ── Shared small widgets ─────────────────────────────────────────────────

  Widget _sectionHeader(String title) {
    return Text(
      title.toUpperCase(),
      style: GoogleFonts.inter(
          fontSize: 10,
          fontWeight: FontWeight.bold,
          color: const Color(0xFF8B949E),
          letterSpacing: 0.8),
    );
  }

  Widget _buildTag(String text) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: const Color(0xFF21262D),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: const Color(0xFF30363D)),
      ),
      child: Text(text,
          style:
              const TextStyle(fontSize: 11, color: Color(0xFF8B949E))),
    );
  }
}
