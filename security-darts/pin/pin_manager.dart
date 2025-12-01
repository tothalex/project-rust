import 'dart:convert';

import 'package:blockben/model/app_auth_type.dart';
import 'package:blockben/repositories/credential_repository.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/crypto/crypto_manager.dart';
import 'package:blockben/utils/optional_utils.dart';

abstract class PinManager {
  Future<bool> hasPin();
  Future<void> savePin(String pinCode);
  Future<bool> verifyPin(String pinCode);
  Future<void> updatePin(String pinCode);
}

class PinManagerImpl extends PinManager {
  final CredentialRepository _credentialRepository;
  final CryptoManager _cryptoManager;
  PinManagerImpl(this._credentialRepository, this._cryptoManager);

  @override
  Future<bool> hasPin() async => await _credentialRepository.hasCredential();

  @override
  Future<void> savePin(String pinCode) async {
    final signatureWithPublicKeyHex = await _cryptoManager.sign(
      data: pinCode.toByteArray(),
      keyAlias: pinSigKey,
    );
    await _credentialRepository.insertCredential(
      signature: signatureWithPublicKeyHex.$1,
      publicKey: signatureWithPublicKeyHex.$2,
      loginType: AppAuthType.pin,
    );
  }

  @override
  Future<void> updatePin(String pinCode) async {
    final signatureResult = await _cryptoManager.sign(
      data: pinCode.toByteArray(),
      keyAlias: pinSigKey,
    );

    final credential = await _credentialRepository.getCredential();
    final credentialId = credential?.credentialId;

    if (credentialId != null) {
      await _credentialRepository.updateCredential(
        credentialId: credentialId,
        signature: signatureResult.$1,
        publicKey: signatureResult.$2,
      );
    }
  }

  @override
  Future<bool> verifyPin(String pinCode) async {
    final credential = await _credentialRepository.getCredential();

    bool isVerified = false;

    credential?.credentialId.ifNotNull((id) {
      isVerified = _cryptoManager.verify(
        data: pinCode.toByteArray(),
        signature: credential.pinSignature,
        publicKey: credential.pinSignaturePublicKey,
      );
    });

    return isVerified;
  }

  static const pinSigKey = 'PIN_SIG_KEY';
}

extension StringToByteArray on String {
  ByteArray toByteArray() {
    return ByteArray.fromList(utf8.encode(this));
  }
}

extension ByteArrayToString on ByteArray {
  String toStringFromByteArray() {
    return utf8.decode(this, allowMalformed: true);
  }
}
