import 'package:blockben/model/constants.dart';
import 'package:blockben/secret/bls/secret_key.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/crypto/crypto_manager.dart';
import 'package:blockben/secret/crypto/hasher.dart';
import 'package:blockben/secret/pvsh/hiver.dart';

abstract class SecretKeyManager {
  Future<HexString> encrypt(HexString secretKey, SignatureHex signatureHex);
  Future<(SecretKeyHex, PublicKeyHex)> decrypt(
    HexString encryptedSecretKey,
    SignatureHex signatureHex,
  );
}

class SecretKeyManagerImpl implements SecretKeyManager {
  SecretKeyManagerImpl(this._cryptoManager, this._hasher);

  final CryptoManager _cryptoManager;
  final Hasher _hasher;

  @override
  Future<HexString> encrypt(
    HexString secretKey,
    SignatureHex signatureHex,
  ) async {
    final helperHash = _hasher
        .sha512Hash(Constants.dbEncryptionHelperString)
        .byteArrayToHexStr();
    final finalHash = _hasher.sha512Hash('$helperHash$signatureHex');
    return (await _cryptoManager.encrypt(
      secretKey.hexStrToByteArray(),
      finalHash.byteArrayToHexStr(),
    ))
        .byteArrayToHexStr();
  }

  @override
  Future<(SecretKeyHex, PublicKeyHex)> decrypt(
    HexString encryptedSecretKey,
    SignatureHex signatureHex,
  ) async {
    final helperHash = _hasher
        .sha512Hash(Constants.dbEncryptionHelperString)
        .byteArrayToHexStr();
    final finalHash = _hasher.sha512Hash('$helperHash$signatureHex');
    final decrypted = await _cryptoManager.decrypt(
      encryptedSecretKey.hexStrToByteArray(),
      finalHash.byteArrayToHexStr(),
    );
    final secretKey = SecretKey()..deserialize(decrypted);
    final publicKeyHex = secretKey.publicKey.serialize().byteArrayToHexStr();

    return (secretKey.serialize().byteArrayToHexStr(), publicKeyHex);
  }
}
