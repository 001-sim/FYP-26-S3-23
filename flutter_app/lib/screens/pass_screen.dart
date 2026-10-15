import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../app_state.dart';
import '../core/pass_token.dart';
import '../models/user_profile.dart';
import '../ui/components.dart';
import '../ui/tokens.dart';
import 'logout_screen.dart';

/// Figma 03 — Dynamic QR Pass, and 09 — QR Pass Expired (refreshing).
/// User story #3: short-lived, single-use, auto-refreshing QR code.
class PassScreen extends StatefulWidget {
  const PassScreen({super.key});

  @override
  State<PassScreen> createState() => _PassScreenState();
}

class _PassScreenState extends State<PassScreen> with WidgetsBindingObserver {
  /// How long the "Pass Expired / Refreshing pass…" state stays visible.
  static const _refreshDelay = Duration(milliseconds: 900);

  PassToken? _pass;
  bool _refreshing = false;
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _ticker = Timer.periodic(const Duration(milliseconds: 250), (_) => _tick());
    _refresh(initial: true);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _ticker?.cancel();
    super.dispose();
  }

  /// Hide the pass as soon as the app leaves the foreground.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) context.read<AppState>().lockPass();
  }

  void _tick() {
    if (!mounted) return;
    final app = context.read<AppState>();
    if (!app.isUnlocked) {
      app.lockPass(); // 2-minute limit reached -> back to "Verify It's You"
      return;
    }
    final pass = _pass;
    if (pass != null && !_refreshing && nowSeconds() >= pass.expiresAt) {
      _refresh();
    } else {
      setState(() {});
    }
  }

  Future<void> _refresh({bool initial = false}) async {
    if (_refreshing) return;
    setState(() => _refreshing = true);
    try {
      if (!initial) await Future.delayed(_refreshDelay);
      if (!mounted) return;
      final pass = await context.read<AppState>().generatePass();
      if (mounted) setState(() => _pass = pass);
    } catch (e) {
      // Unreachable backend switches screen via AppState; show anything else.
      if (mounted && context.read<AppState>().stage == AppStage.pass) showMessage(context, e);
    } finally {
      if (mounted) setState(() => _refreshing = false);
    }
  }

  static String maskId(String id) =>
      id.length <= 6 ? id : '${id.substring(0, 4)}••••${id.substring(id.length - 2)}';

  @override
  Widget build(BuildContext context) {
    final user = context.watch<AppState>().user!;
    final pass = _pass;
    final remaining = pass == null ? 0 : (pass.expiresAt - nowSeconds()).clamp(0, passValiditySeconds);
    final preparing = pass == null;
    final expired = preparing || remaining == 0;
    final roleLabel = user.role == UserRole.student ? 'Student' : 'Staff';

    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: kPagePadding,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 34),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: Padding(
                      padding: const EdgeInsets.only(top: 18),
                      child: Text('Your Access Pass', style: AppText.stateTitle),
                    ),
                  ),
                  _CloseButton(
                    onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const LogoutScreen())),
                  ),
                ],
              ),
              const SizedBox(height: 13),
              Text(user.name, style: AppText.name),
              const SizedBox(height: 3),
              Text('$roleLabel · ${maskId(user.campusId)}', style: AppText.small),
              const SizedBox(height: 31),
              Center(child: _qrBox(pass, expired, preparing)),
              const SizedBox(height: 14),
              SizedBox(
                width: double.infinity,
                child: Text(
                  preparing ? 'Preparing pass…' : (expired ? 'Pass Expired' : 'Expires in ${remaining}s'),
                  textAlign: TextAlign.center,
                  style: AppText.inter(14, FontWeight.w600,
                      preparing ? AppColors.textSecondary : (expired ? AppColors.red : AppColors.amber)),
                ),
              ),
              const SizedBox(height: 11),
              Center(
                child: SizedBox(
                  width: 240,
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(3),
                    child: LinearProgressIndicator(
                      value: expired ? 0 : remaining / passValiditySeconds,
                      minHeight: 6,
                      backgroundColor: AppColors.track,
                      color: AppColors.primary,
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 18),
              SizedBox(
                width: double.infinity,
                child: Text(
                  expired
                      ? 'Single-use · A new code appears automatically'
                      : 'Single-use · Refreshes automatically every ${passValiditySeconds}s',
                  textAlign: TextAlign.center,
                  style: AppText.caption,
                ),
              ),
              const Spacer(),
              if (expired && !preparing)
                SizedBox(
                  width: double.infinity,
                  child: Text('This code can no longer be scanned. Please wait for the refresh.',
                      textAlign: TextAlign.center, style: AppText.footnote),
                ),
              const SizedBox(height: 16),
            ],
          ),
        ),
      ),
    );
  }

  Widget _qrBox(PassToken? pass, bool expired, bool preparing) {
    return Container(
      width: 240,
      height: 240,
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.border),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(16),
        child: Stack(
          fit: StackFit.expand,
          children: [
            if (pass != null)
              Padding(
                padding: const EdgeInsets.all(12),
                child: QrImageView(
                  data: pass.token,
                  version: QrVersions.auto,
                  errorCorrectionLevel: QrErrorCorrectLevel.L,
                  backgroundColor: Colors.white,
                  padding: EdgeInsets.zero,
                  eyeStyle: const QrEyeStyle(eyeShape: QrEyeShape.square, color: AppColors.qrInk),
                  dataModuleStyle:
                      const QrDataModuleStyle(dataModuleShape: QrDataModuleShape.square, color: AppColors.qrInk),
                ),
              ),
            if (expired)
              Container(
                color: Colors.white.withAlpha(224), // rgba(255,255,255,0.88)
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const SizedBox(
                      width: 32,
                      height: 32,
                      child: CircularProgressIndicator(strokeWidth: 3, color: AppColors.primary),
                    ),
                    const SizedBox(height: 14),
                    Text(preparing ? 'Generating pass…' : 'Refreshing pass…', style: AppText.inter(14, FontWeight.w600, AppColors.textPrimary)),
                    const SizedBox(height: 7),
                    Text('New code in a moment', style: AppText.caption),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// Red ✕ circle (top-right of Figma 03).
class _CloseButton extends StatelessWidget {
  const _CloseButton({required this.onTap});
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) => Material(
        color: AppColors.red,
        shape: const CircleBorder(),
        child: InkWell(
          customBorder: const CircleBorder(),
          onTap: onTap,
          child: const SizedBox(width: 32, height: 32, child: Icon(Icons.close, size: 18, color: Colors.white)),
        ),
      );
}
