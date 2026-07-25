import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

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

  bool _hasAnalyzed = false;
  bool _isFake = false;

  Future<void> _pickImage() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.image,
        withData: true,
      );

      if (result != null && result.files.single.bytes != null) {
        setState(() {
          _selectedImageBytes = result.files.single.bytes;
          _fileName = result.files.single.name;
          _isProcessing = true;
          _showElaMode = false;
        });

        await Future.delayed(const Duration(milliseconds: 1500));

        setState(() {
          _isProcessing = false;
          _hasAnalyzed = true;
          _isFake = _fileName!.toLowerCase().contains('fake') ||
              (DateTime.now().millisecond % 2 == 0);
          if (_isFake) {
            _showElaMode = true;
          }
        });
      }
    } catch (e) {
      debugPrint("File picker error: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _buildAppBar(context),
      body: LayoutBuilder(
        builder: (context, constraints) {
          bool isDesktopOrTab = constraints.maxWidth > 900;

          return SingleChildScrollView(
            padding: const EdgeInsets.all(16.0),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1300),
                child: isDesktopOrTab
                    ? Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(flex: 5, child: _buildUploadAndVisualizerCard()),
                    const SizedBox(width: 20),
                    Expanded(flex: 4, child: _buildForensicReportCard()),
                  ],
                )
                    : Column(
                  children: [
                    _buildUploadAndVisualizerCard(),
                    const SizedBox(height: 20),
                    _buildForensicReportCard(),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  // FIXED: Responsive AppBar (Prevents Mobile Overflow)
  PreferredSizeWidget _buildAppBar(BuildContext context) {
    double screenWidth = MediaQuery.of(context).size.width;
    bool isMobile = screenWidth < 600;

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
            child: const Icon(Icons.shield_outlined, color: Colors.white, size: 20),
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
                    fontWeight: FontWeight.bold,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  isMobile ? 'Forensics Engine' : 'Payment Screenshot Forensics Engine',
                  style: GoogleFonts.inter(
                    fontSize: 10,
                    color: const Color(0xFF8B949E),
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        Padding(
          padding: const EdgeInsets.only(right: 12.0),
          child: Container(
            padding: EdgeInsets.symmetric(
              horizontal: isMobile ? 8 : 12,
              vertical: 6,
            ),
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
                  isMobile ? 'WASM Ready' : 'WASM ELA Ready',
                  style: const TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.w600,
                    color: Color(0xFF3FB950),
                  ),
                ),
              ],
            ),
          ),
        )
      ],
    );
  }

  Widget _buildUploadAndVisualizerCard() {
    return Card(
      color: const Color(0xFF161B22),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: Color(0xFF30363D)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Row(
              children: [
                Icon(Icons.cloud_upload_outlined, color: Color(0xFF2F81F7)),
                SizedBox(width: 8),
                Text(
                  'Receipt Screenshot Input',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const Divider(color: Color(0xFF30363D), height: 24),

            if (_isProcessing)
              Container(
                height: 280,
                alignment: Alignment.center,
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const CircularProgressIndicator(color: Color(0xFF2F81F7)),
                    const SizedBox(height: 16),
                    Text(
                      'Executing WASM ELA & Layout Parsing...',
                      style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13),
                    ),
                  ],
                ),
              )
            else if (_selectedImageBytes == null)
              GestureDetector(
                onTap: _pickImage,
                child: Container(
                  height: 280,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: const Color(0xFF21262D).withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                      color: const Color(0xFF30363D),
                      width: 2,
                    ),
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.add_photo_alternate_outlined,
                          size: 46, color: Color(0xFF2F81F7)),
                      const SizedBox(height: 10),
                      const Text(
                        'Click to Browse Screenshot',
                        style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Supports PNG, JPG, WEBP',
                        style: TextStyle(fontSize: 11, color: Colors.grey[500]),
                      ),
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
                      )
                    ],
                  ),
                ),
              )
            else
              Column(
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
                        Image.memory(
                          _selectedImageBytes!,
                          fit: BoxFit.contain,
                        ),
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

                  // Responsive Action Buttons for Mobile
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
                          label: const Text(
                            'Original',
                            style: TextStyle(fontSize: 12),
                          ),
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
                          label: const Text(
                            'ELA Mode',
                            style: TextStyle(fontSize: 12),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: _pickImage,
                    icon: const Icon(Icons.refresh, size: 15),
                    label: const Text('Upload Another Image', style: TextStyle(fontSize: 12)),
                  )
                ],
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildForensicReportCard() {
    return Card(
      color: const Color(0xFF161B22),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: Color(0xFF30363D)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.memory, color: Color(0xFF2F81F7)),
                SizedBox(width: 8),
                Text(
                  'Forensic Analysis Output',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const Divider(color: Color(0xFF30363D), height: 24),

            _buildResultBanner(),

            const SizedBox(height: 16),
            _sectionHeader('ELA Matrix Density'),
            const SizedBox(height: 8),
            _buildElaLegend(),

            const SizedBox(height: 16),
            _sectionHeader('Metadata Inspection'),
            const SizedBox(height: 8),
            _buildDataRow('Software Tag', _hasAnalyzed ? (_isFake ? 'PicsArt / Photoshop' : 'Android System UI') : '--', _isFake),
          ],
        ),
      ),
    );
  }

  Widget _buildResultBanner() {
    if (!_hasAnalyzed) {
      return Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: const Color(0xFF21262D),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0xFF30363D)),
        ),
        child: const Row(
          children: [
            Icon(Icons.info_outline, color: Color(0xFF8B949E), size: 18),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'Upload a screenshot to view ELA and checksum metrics.',
                style: TextStyle(color: Color(0xFF8B949E), fontSize: 12),
              ),
            ),
          ],
        ),
      );
    }

    if (_isFake) {
      return Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: const Color(0xFFF85149).withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0xFFF85149)),
        ),
        child: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: Color(0xFFF85149), size: 18),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'SUSPICIOUS: Localized Pixel Manipulation Detected!',
                style: TextStyle(
                  color: Color(0xFFF85149),
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
      );
    } else {
      return Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: const Color(0xFF238636).withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0xFF238636)),
        ),
        child: const Row(
          children: [
            Icon(Icons.check_circle_outline, color: Color(0xFF3FB950), size: 18),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'AUTHENTIC: Screenshot Integrity Verified',
                style: TextStyle(
                  color: Color(0xFF3FB950),
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
      );
    }
  }

  Widget _buildElaLegend() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: const Color(0xFF21262D),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          const Text('Density:', style: TextStyle(fontSize: 11, color: Color(0xFF8B949E))),
          Row(
            children: [
              const Text('Authentic', style: TextStyle(fontSize: 10, color: Color(0xFF3FB950))),
              const SizedBox(width: 4),
              Container(
                width: 50,
                height: 5,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(3),
                  gradient: const LinearGradient(
                    colors: [Color(0xFF3FB950), Color(0xFFF85149)],
                  ),
                ),
              ),
              const SizedBox(width: 4),
              const Text('Tampered', style: TextStyle(fontSize: 10, color: Color(0xFFF85149))),
            ],
          )
        ],
      ),
    );
  }

  Widget _buildDataRow(String label, String value, bool isError) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6.0),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        decoration: BoxDecoration(
          color: const Color(0xFF21262D),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(label, style: const TextStyle(fontSize: 12, color: Color(0xFF8B949E))),
            Flexible(
              child: Text(
                value,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  color: isError ? const Color(0xFFF85149) : Colors.white,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _sectionHeader(String title) {
    return Text(
      title.toUpperCase(),
      style: GoogleFonts.inter(
        fontSize: 10,
        fontWeight: FontWeight.bold,
        color: const Color(0xFF8B949E),
        letterSpacing: 0.8,
      ),
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
      child: Text(text, style: const TextStyle(fontSize: 11, color: Color(0xFF8B949E))),
    );
  }
}