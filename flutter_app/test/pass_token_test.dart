import 'package:flutter_test/flutter_test.dart';
import 'package:fyp_app/core/jws.dart';
import 'package:fyp_app/core/pass_token.dart';

void main() {
  final issuer = EcKeyPair.generate();
  final device = EcKeyPair.generate();
  final credential = issueCredential(
    issuerKey: issuer,
    issuer: 'test-issuer',
    userId: 'u1',
    name: 'Test Student',
    role: 'student',
    campusId: 'S1234567',
    deviceJwk: device.publicJwk,
  );
  PassVerifier verifier() => PassVerifier(trustedIssuerKeys: {issuer.kid: issuer.publicJwk});

  test('valid pass is granted once, then blocked as replay (#10)', () {
    final v = verifier();
    final pass = createPassToken(credential: credential, deviceKey: device, userId: 'u1');
    expect(v.verify(pass.token).result, PassCheck.granted);
    expect(v.verify(pass.token).result, PassCheck.replayed);
  });

  test('expired pass is rejected, small clock skew is tolerated (#9)', () {
    final now = nowSeconds();
    final pass = createPassToken(credential: credential, deviceKey: device, userId: 'u1', now: now - 33);
    expect(verifier().verify(pass.token, now: now).result, PassCheck.granted); // 3s late, within 5s skew
    final old = createPassToken(credential: credential, deviceKey: device, userId: 'u1', now: now - 60);
    expect(verifier().verify(old.token, now: now).result, PassCheck.expired);
  });

  test('pass signed by a different device key is rejected', () {
    final pass = createPassToken(credential: credential, deviceKey: EcKeyPair.generate(), userId: 'u1');
    expect(verifier().verify(pass.token).result, PassCheck.badDeviceSignature);
  });

  test('credential from an untrusted issuer is rejected', () {
    final fakeIssuer = EcKeyPair.generate();
    final fakeCred = issueCredential(
      issuerKey: fakeIssuer,
      issuer: 'evil',
      userId: 'u1',
      name: 'x',
      role: 'staff',
      campusId: 'x',
      deviceJwk: device.publicJwk,
    );
    final pass = createPassToken(credential: fakeCred, deviceKey: device, userId: 'u1');
    expect(verifier().verify(pass.token).result, PassCheck.unknownIssuer);
  });

  test('tampered payload or garbage is rejected', () {
    final pass = createPassToken(credential: credential, deviceKey: device, userId: 'u1');
    final parts = pass.token.split('.');
    final payload = b64urlJsonDecode(parts[1])..['exp'] = 9999999999;
    final tampered = '${parts[0]}.${b64urlJson(payload)}.${parts[2]}';
    expect(verifier().verify(tampered).result, PassCheck.badDeviceSignature);
    expect(verifier().verify('not-a-token').result, PassCheck.malformed);
  });
}
