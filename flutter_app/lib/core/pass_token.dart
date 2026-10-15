// Access-pass token format (shared contract with the scanner + backend).
//
// QR content = compact JWS signed by the DEVICE key:
//   header : { alg: ES256, typ: "qrpass+jwt", kid: <device key id> }
//   payload: { jti, sub, iat, exp (= iat + 30s), cred: <credential JWS> }
//
// cred = compact JWS signed by the ISSUER (backend):
//   header : { alg: ES256, typ: "cred+jwt", kid: <issuer key id> }
//   payload: { iss, sub, name, role, campusId, iat, exp, cnf: { jwk: <device public key> } }
//
// The scanner trusts the issuer key, uses cred.cnf.jwk to check the device
// signature, then checks expiry (with clock skew) and that the jti is unused.
import 'jws.dart';

const int passValiditySeconds = 30;
const int defaultClockSkewSeconds = 5;

int nowSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

/// Backend side: binds a user + device public key into a signed credential.
String issueCredential({
  required EcKeyPair issuerKey,
  required String issuer,
  required String userId,
  required String name,
  required String role,
  required String campusId,
  required Map<String, String> deviceJwk,
  Duration ttl = const Duration(hours: 24),
  int? now,
}) {
  final iat = now ?? nowSeconds();
  return signJws(
    header: {'typ': 'cred+jwt', 'kid': issuerKey.kid},
    payload: {
      'iss': issuer,
      'sub': userId,
      'name': name,
      'role': role,
      'campusId': campusId,
      'iat': iat,
      'exp': iat + ttl.inSeconds,
      'cnf': {'jwk': deviceJwk},
    },
    key: issuerKey,
  );
}

class PassToken {
  PassToken({required this.token, required this.jti, required this.issuedAt, required this.expiresAt});

  final String token;
  final String jti;
  final int issuedAt;
  final int expiresAt;
}

/// Mobile side: creates a fresh short-lived pass signed by the device key.
PassToken createPassToken({
  required String credential,
  required EcKeyPair deviceKey,
  required String userId,
  int validitySeconds = passValiditySeconds,
  int? now,
}) {
  final iat = now ?? nowSeconds();
  final jti = randomId();
  final exp = iat + validitySeconds;
  final token = signJws(
    header: {'typ': 'qrpass+jwt', 'kid': deviceKey.kid},
    payload: {'jti': jti, 'sub': userId, 'iat': iat, 'exp': exp, 'cred': credential},
    key: deviceKey,
  );
  return PassToken(token: token, jti: jti, issuedAt: iat, expiresAt: exp);
}

/// Returns the `exp` (seconds) of a JWS without verifying it, or null.
int? peekExpiry(String jws) {
  try {
    return (DecodedJws.parse(jws).payload['exp'] as num).toInt();
  } catch (_) {
    return null;
  }
}

enum PassCheck {
  granted,
  malformed,
  unknownIssuer,
  badIssuerSignature,
  credentialExpired,
  badDeviceSignature,
  subjectMismatch,
  notYetValid,
  expired,
  replayed,
}

class PassVerification {
  PassVerification(this.result, {this.userId, this.name, this.role, this.jti});

  final PassCheck result;
  final String? userId;
  final String? name;
  final String? role;
  final String? jti;

  bool get isGranted => result == PassCheck.granted;
}

/// Verifies pass tokens. Used for self-tests here; the same logic is what the
/// scanner (offline mode) and backend (/verify) must implement.
class PassVerifier {
  PassVerifier({required this.trustedIssuerKeys, this.clockSkewSeconds = defaultClockSkewSeconds});

  /// Issuer key id -> public JWK (the pre-loaded trust anchors).
  final Map<String, Map<String, dynamic>> trustedIssuerKeys;
  final int clockSkewSeconds;

  /// Used token ids -> their expiry, for single-use (replay) protection.
  final Map<String, int> _usedJti = {};

  PassVerification verify(String token, {int? now}) {
    final t = now ?? nowSeconds();
    _usedJti.removeWhere((_, exp) => exp + clockSkewSeconds < t);

    final DecodedJws pass;
    final DecodedJws cred;
    try {
      pass = DecodedJws.parse(token);
      cred = DecodedJws.parse(pass.payload['cred'] as String);
    } catch (_) {
      return PassVerification(PassCheck.malformed);
    }

    // 1. Credential must be signed by a trusted issuer.
    final issuerJwk = trustedIssuerKeys[cred.header['kid']];
    if (issuerJwk == null) return PassVerification(PassCheck.unknownIssuer);
    if (!cred.verifyWith(issuerJwk)) return PassVerification(PassCheck.badIssuerSignature);

    final c = cred.payload;
    final p = pass.payload;
    PassVerification info(PassCheck r) => PassVerification(r,
        userId: c['sub'] as String?, name: c['name'] as String?, role: c['role'] as String?, jti: p['jti'] as String?);

    final credExp = c['exp'];
    if (credExp is! num || credExp + clockSkewSeconds < t) return info(PassCheck.credentialExpired);

    // 2. Pass must be signed by the device key bound inside the credential.
    final deviceJwk = (c['cnf'] as Map?)?['jwk'];
    if (deviceJwk is! Map<String, dynamic> || !pass.verifyWith(deviceJwk)) {
      return info(PassCheck.badDeviceSignature);
    }
    if (p['sub'] != c['sub']) return info(PassCheck.subjectMismatch);

    // 3. Time window (with clock-skew tolerance).
    final iat = p['iat'];
    final exp = p['exp'];
    if (iat is! num || exp is! num || exp - iat > 60) return info(PassCheck.malformed);
    if (iat - clockSkewSeconds > t) return info(PassCheck.notYetValid);
    if (exp + clockSkewSeconds < t) return info(PassCheck.expired);

    // 4. Single use.
    final jti = p['jti'];
    if (jti is! String || jti.isEmpty) return info(PassCheck.malformed);
    if (_usedJti.containsKey(jti)) return info(PassCheck.replayed);
    _usedJti[jti] = exp.toInt();

    return info(PassCheck.granted);
  }
}
