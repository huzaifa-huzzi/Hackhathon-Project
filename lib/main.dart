import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:hackhaton_project/Frontend/DashboardScreen.dart';

void main() {
  runApp(const SikkaCheckApp());
}

class SikkaCheckApp extends StatelessWidget {
  const SikkaCheckApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SikkaCheck | Screenshot Forensics',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0D1117),
        cardColor: const Color(0xFF161B22),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF2F81F7),
          secondary: Color(0xFF3FB950),
          error: Color(0xFFF85149),
          surface: Color(0xFF161B22),
        ),
        textTheme: GoogleFonts.interTextTheme(ThemeData.dark().textTheme),
      ),
      home: const DashboardScreen(),
    );
  }
}
