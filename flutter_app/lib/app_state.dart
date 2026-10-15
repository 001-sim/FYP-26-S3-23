import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'core/pass_token.dart';
import 'models/user_profile.dart';
import 'services/backend_api.dart';
import 'services/biometric_service.dart';
import 'services/device_key_service.dart';

/// Which screen the app should show (see AppGate in main.dart).
enum AppStage {
  loading,
  signedOut, //           04 Login (01 Enrol / 11 Submitted are pushed on top)
  verify, //              02 Biometric Unlock
  verifyFailed, //        06 Biometric Failed (Retry)
  accountLocked, //       10 Account Locked
  backendUnreachable, //  07 Backend Unreachable
  pass, //                03 Dynamic QR Pass / 09 Pass Expired
}

class AppState extends ChangeNotifier {
  AppState({
    required this.api,
    BiometricService? biometrics,
    DeviceKeyService? keys,
    FlutterSecureStorage? storage,
  })  : biometrics = biometrics ?? BiometricService(),
        keys = keys ?? DeviceKeyService(),
        _storage = storage ?? const FlutterSecureStorage();

  final BackendApi api;
  final BiometricService biometrics;
  final DeviceKeyService keys;
  final FlutterSecureStorage _storage;

  static const maxAttempts = 3;
  static const lockDuration = Duration(minutes: 15);
  static const unlockDuration = Duration(minutes: 2);

  static const _userKey = 'session.user';
  static const _credKey = 'session.credential';
  static const _failsKey = 'security.failedAttempts';
  static const _lockKey = 'security.lockedUntil';

  AppStage stage = AppStage.loading;
  UserProfile? user;
  String? _credential;

  int failedAttempts = 0;
  DateTime? lockedUntil;
  DateTime? unlockedUntil;
  String errorDetail = '';

  int get triesLeft => maxAttempts - failedAttempts;
  bool get isLocked => lockedUntil != null && DateTime.now().isBefore(lockedUntil!);
  bool get isUnlocked => unlockedUntil != null && DateTime.now().isBefore(unlockedUntil!);

  void _go(AppStage next) {
    stage = next;
    notifyListeners();
  }

  // ---------------------------------------------------------------- startup
  Future<void> init() async {
    final rawUser = await _storage.read(key: _userKey);
    if (rawUser != null) {
      user = UserProfile.fromJson(jsonDecode(rawUser) as Map<String, dynamic>);
      _credential = await _storage.read(key: _credKey);
    }
    failedAttempts = int.tryParse(await _storage.read(key: _failsKey) ?? '') ?? 0;
    final lock = int.tryParse(await _storage.read(key: _lockKey) ?? '');
    lockedUntil = lock == null ? null : DateTime.fromMillisecondsSinceEpoch(lock);
    _go(user == null ? AppStage.signedOut : (isLocked ? AppStage.accountLocked : AppStage.verify));
  }

  // ---------------------------------------------------------- enrol / login
  Future<EnrolmentResult> enrol({
    required String name,
    required String email,
    required String campusId,
    required String password,
    required UserRole role,
  }) =>
      api.enrol(name: name, email: email, campusId: campusId, password: password, role: role);

  Future<void> login(String identifier, String password) async {
    final profile = await api.login(identifier: identifier, password: password);
    final previous = user;
    user = profile;
    await _storage.write(key: _userKey, value: jsonEncode(profile.toJson()));
    // A device key belongs to one user – start fresh if someone else logs in.
    if (previous?.id != profile.id || _credential == null) {
      await keys.deleteKey();
      await _storage.delete(key: _credKey);
      _credential = null;
    }
    _go(isLocked ? AppStage.accountLocked : AppStage.verify);
  }

  Future<void> logout() async {
    await keys.deleteKey();
    await _storage.delete(key: _userKey);
    await _storage.delete(key: _credKey);
    user = null;
    _credential = null;
    unlockedUntil = null;
    _go(AppStage.signedOut);
  }

  // -------------------------------------------------------- biometric (#2)
  /// "Use Face ID" / "Try Again" / "Retry".
  /// Returns a message to show if biometrics are not set up on the phone.
  Future<String?> verify() async {
    if (isLocked) {
      _go(AppStage.accountLocked);
      return null;
    }
    if (!biometrics.simulateFailureOnce && !await biometrics.isAvailable()) {
      return 'No Face ID or fingerprint is set up on this phone. Add one in Settings first.';
    }
    final ok = await biometrics.authenticate('Verify it\'s you to show your access pass');
    if (!ok) {
      await registerFailedAttempt();
      return null;
    }
    await _setFailedAttempts(0);

    try {
      await _ensureDeviceCredential();
    } on BackendUnreachableException catch (e) {
      errorDetail = 'Error: ${e.message}';
      _go(AppStage.backendUnreachable);
      return null;
    }
    unlockedUntil = DateTime.now().add(unlockDuration);
    _go(AppStage.pass);
    return null;
  }

  /// Counts a failed biometric attempt; locks the device after 3.
  Future<void> registerFailedAttempt() async {
    await _setFailedAttempts(failedAttempts + 1);
    if (failedAttempts >= maxAttempts) {
      lockedUntil = DateTime.now().add(lockDuration);
      await _storage.write(key: _lockKey, value: lockedUntil!.millisecondsSinceEpoch.toString());
      await _setFailedAttempts(0);
      _go(AppStage.accountLocked);
    } else {
      _go(AppStage.verifyFailed);
    }
  }

  Future<void> _setFailedAttempts(int n) async {
    failedAttempts = n;
    await _storage.write(key: _failsKey, value: '$n');
  }

  /// Called by the lock screen when the 15 minutes are over.
  Future<void> lockExpired() async {
    lockedUntil = null;
    await _storage.delete(key: _lockKey);
    _go(AppStage.verify);
  }

  void backToVerify() => _go(AppStage.verify);

  /// ✕ on the pass, app sent to background, or 2-minute timeout.
  void lockPass() {
    unlockedUntil = null;
    if (stage == AppStage.pass) _go(AppStage.verify);
  }

  /// Creates the device key + gets the backend credential on first use, and
  /// renews the credential when it is about to expire.
  Future<void> _ensureDeviceCredential() async {
    var key = await keys.loadKey();
    final exp = _credential == null ? null : peekExpiry(_credential!);
    if (key != null && exp != null && exp - 60 > nowSeconds()) return;
    key ??= await keys.createKey();
    final credential = await api.issueCredential(user: user!, deviceJwk: key.publicJwk);
    await _storage.write(key: _credKey, value: credential);
    _credential = credential;
  }

  // ----------------------------------------------------------- pass (#3)
  /// Builds a fresh single-use QR token (valid [passValiditySeconds]).
  Future<PassToken> generatePass() async {
    if (!isUnlocked) throw BackendException('Pass is locked. Verify it\'s you first.');
    try {
      await _ensureDeviceCredential();
    } on BackendUnreachableException catch (e) {
      errorDetail = 'Error: ${e.message}';
      _go(AppStage.backendUnreachable);
      rethrow;
    }
    final key = (await keys.loadKey())!;
    return createPassToken(credential: _credential!, deviceKey: key, userId: user!.id);
  }
}
