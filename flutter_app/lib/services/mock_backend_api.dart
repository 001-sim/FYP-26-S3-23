import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../core/jws.dart';
import '../core/pass_token.dart' as pass;
import '../models/user_profile.dart';
import 'backend_api.dart';

/// On-device stand-in for the real backend. FOR DEVELOPMENT ONLY:
/// the "issuer" private key lives on the phone here, which would defeat the
/// security model in production. Replace with the real API later.
///
/// Enrolments are returned as "Pending Review" (as in the Figma flow) but the
/// mock approves them immediately so you can log in straight away.
class MockBackendApi implements BackendApi {
  MockBackendApi({FlutterSecureStorage? storage}) : _storage = storage ?? const FlutterSecureStorage();

  static const _usersKey = 'mock.users';
  static const _issuerKey = 'mock.issuerKey';
  static const issuerName = 'fyp-mock-issuer';

  final FlutterSecureStorage _storage;

  // Demo switches used by the "→ Demo: …" buttons in the wireframe.
  bool simulateDuplicateIdOnce = false;
  bool simulateUnreachableOnce = false;

  Future<void> _latency() => Future.delayed(const Duration(milliseconds: 400));

  Future<void> _maybeUnreachable() async {
    if (simulateUnreachableOnce) {
      simulateUnreachableOnce = false;
      await Future.delayed(const Duration(seconds: 1));
      throw BackendUnreachableException();
    }
  }

  Future<Map<String, dynamic>> _users() async {
    final raw = await _storage.read(key: _usersKey);
    return raw == null ? {} : jsonDecode(raw) as Map<String, dynamic>;
  }

  Future<EcKeyPair> _issuer() async {
    final raw = await _storage.read(key: _issuerKey);
    if (raw != null) return EcKeyPair.fromStorage(jsonDecode(raw) as Map<String, dynamic>);
    final key = EcKeyPair.generate();
    await _storage.write(key: _issuerKey, value: jsonEncode(key.toStorage()));
    return key;
  }

  String _hash(String salt, String password) => b64url(sha256(utf8.encode('$salt:$password')));

  @override
  Future<EnrolmentResult> enrol({
    required String name,
    required String email,
    required String campusId,
    required String password,
    required UserRole role,
  }) async {
    await _latency();
    await _maybeUnreachable();
    final idLabel = role == UserRole.student ? 'Student ID' : 'Staff ID';
    final users = await _users();
    final emailKey = email.trim().toLowerCase();
    final id = campusId.trim().toUpperCase();
    final idTaken = users.values.any((u) => ((u as Map)['profile'] as Map)['campusId'] == id);
    if (simulateDuplicateIdOnce || idTaken) {
      simulateDuplicateIdOnce = false;
      throw DuplicateIdException(idLabel);
    }
    if (users.containsKey(emailKey)) throw BackendException('An account with this email already exists.');

    final profile = UserProfile(id: randomId(9), name: name.trim(), email: emailKey, campusId: id, role: role);
    final salt = randomId();
    users[emailKey] = {'profile': profile.toJson(), 'salt': salt, 'hash': _hash(salt, password)};
    await _storage.write(key: _usersKey, value: jsonEncode(users));
    return EnrolmentResult(profile, EnrolmentStatus.pendingReview);
  }

  @override
  Future<UserProfile> login({required String identifier, required String password}) async {
    await _latency();
    await _maybeUnreachable();
    final users = await _users();
    final key = identifier.trim();
    Map<String, dynamic>? record = users[key.toLowerCase()] as Map<String, dynamic>?;
    record ??= users.values
        .cast<Map<String, dynamic>>()
        .where((u) => (u['profile'] as Map)['campusId'] == key.toUpperCase())
        .firstOrNull;
    if (record == null || record['hash'] != _hash(record['salt'] as String, password)) {
      throw BackendException('Incorrect ID/email or password.');
    }
    return UserProfile.fromJson(record['profile'] as Map<String, dynamic>);
  }

  @override
  Future<String> issueCredential({required UserProfile user, required Map<String, String> deviceJwk}) async {
    await _latency();
    await _maybeUnreachable();
    return pass.issueCredential(
      issuerKey: await _issuer(),
      issuer: issuerName,
      userId: user.id,
      name: user.name,
      role: user.role.name,
      campusId: user.campusId,
      deviceJwk: deviceJwk,
    );
  }

  @override
  Future<Map<String, Map<String, dynamic>>> issuerKeys() async {
    final issuer = await _issuer();
    return {issuer.kid: issuer.publicJwk};
  }
}
