import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'app_state.dart';
import 'screens/account_locked_screen.dart';
import 'screens/backend_unreachable_screen.dart';
import 'screens/login_screen.dart';
import 'screens/pass_screen.dart';
import 'screens/verify_failed_screen.dart';
import 'screens/verify_screen.dart';
import 'services/mock_backend_api.dart';
import 'ui/tokens.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(
    ChangeNotifierProvider(
      // Swap MockBackendApi for the real HTTP API once the backend is ready.
      create: (_) => AppState(api: MockBackendApi())..init(),
      child: const SecureAccessApp(),
    ),
  );
}

class SecureAccessApp extends StatelessWidget {
  const SecureAccessApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecureAccess',
      debugShowCheckedModeBanner: false,
      theme: buildAppTheme(),
      home: const AppGate(),
    );
  }
}

/// Picks the screen for the current state (Figma screen numbers in brackets).
class AppGate extends StatelessWidget {
  const AppGate({super.key});

  @override
  Widget build(BuildContext context) {
    return switch (context.watch<AppState>().stage) {
      AppStage.loading => const Scaffold(body: Center(child: CircularProgressIndicator())),
      AppStage.signedOut => const LoginScreen(), //                  04
      AppStage.verify => const VerifyScreen(), //                     02
      AppStage.verifyFailed => const VerifyFailedScreen(), //         06
      AppStage.accountLocked => const AccountLockedScreen(), //       10
      AppStage.backendUnreachable => const BackendUnreachableScreen(), // 07
      AppStage.pass => const PassScreen(), //                         03 / 09
    };
  }
}
