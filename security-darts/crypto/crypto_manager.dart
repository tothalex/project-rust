import 'dart:math';

import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/crypto/keystore_provider.dart';
import 'package:blockben/secret/crypto/secure_storage.dart';
import 'package:blockben/secret/pvsh/hiver.dart';
import 'package:blockben/utils/big_int_utils.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart' hide Digest;

abstract class CryptoManager {
  Future<(SignatureHex, PublicKeyHex)> sign({
    required ByteArray data,
    required String keyAlias,
    bool? deleteKeysAfterSign,
  });

  bool verify({
    required ByteArray data,
    required HexString signature,
    required HexString publicKey,
  });

  Future<ByteArray> encrypt(ByteArray data, String keyAlias);
  Future<ByteArray> decrypt(ByteArray data, String keyAlias);
  Future<ByteArray> aesEncrypt(
    ByteArray data,
    HexString keyHex,
    HexString ivHex,
  );
  Future<ByteArray> aesDecrypt(
    ByteArray data,
    HexString keyHex,
    HexString ivHex,
  );
  ByteArray generate8ByteRandom();
  HexString doubleSha512Hash(ByteArray input);
}

class CryptoManagerImpl implements CryptoManager {
  final SecureStorage _secureStorage;
  final KeystoreProvider _keyStoreProvider;

  CryptoManagerImpl(this._secureStorage, this._keyStoreProvider);

  @override
  Future<(SignatureHex, PublicKeyHex)> sign({
    required ByteArray data,
    required String keyAlias,
    bool? deleteKeysAfterSign,
  }) async {
    final keyPair = _keyStoreProvider.generateRSAKeyPair(keyAlias);
    final privateKey = keyPair.privateKey as RSAPrivateKey;
    final publicKey = keyPair.publicKey as RSAPublicKey;

    final signer = RSASigner(
      RSASignDigest.SHA256,
      publicKey: publicKey,
      privateKey: privateKey,
    );
    final signature = signer.sign(data).bytes;

    final signatureHex = signature.byteArrayToHexStr();
    final publicKeyHex = _publicKeyToHex(publicKey);

    if (deleteKeysAfterSign == true) {
      _secureStorage.delete(keyAlias);
    }

    return (signatureHex, publicKeyHex);
  }

  @override
  bool verify({
    required ByteArray data,
    required HexString signature,
    required HexString publicKey,
  }) {
    try {
      final signer = RSASigner(
        RSASignDigest.SHA256,
        publicKey: hexStringToRSAPublicKey(publicKey),
      );
      final encryptedSigneture = Encrypted.fromBase16(signature);

      return signer.verify(data, encryptedSigneture);
    } catch (e) {
      return false;
    }
  }

  @override
  Future<ByteArray> encrypt(ByteArray data, String keyAlias) async {
    final key = await _keyStoreProvider.getOrCreateAES256Key(keyAlias);
    var iv = await _keyStoreProvider.getIV(keyAlias);
    final hasSavedIv = iv != null;

    if (!hasSavedIv) {
      iv = _generateRandomIV();
    }

    final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
    final encrypted = encrypter.encryptBytes(data, iv: iv);

    if (!hasSavedIv) {
      await _keyStoreProvider.saveIV(keyAlias, iv);
    }

    return ByteArray.fromList(encrypted.bytes);
  }

  @override
  Future<ByteArray> decrypt(ByteArray data, String keyAlias) async {
    final key = await _keyStoreProvider.getAES256Key(keyAlias);
    if (key == null) {
      throw Exception('Can not decrypt without an AES 256 stored!');
    }
    final iv = await _keyStoreProvider.getIV(keyAlias);
    if (iv == null) {
      throw Exception('Can not decrypt without an IV stored!');
    }
    final encrypter = Encrypter(
      AES(key, mode: AESMode.cbc),
    );
    final decrypted = encrypter.decryptBytes(
      Encrypted(data),
      iv: iv,
    );
    return ByteArray.fromList(decrypted);
  }

  @override
  Future<ByteArray> aesEncrypt(
    ByteArray data,
    HexString keyHex,
    HexString ivHex,
  ) async {
    final key = Key.fromBase16(keyHex);
    final iv = IV.fromBase16(ivHex);

    final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
    final encrypted = encrypter.encryptBytes(data, iv: iv);

    return ByteArray.fromList(encrypted.bytes);
  }

  @override
  Future<ByteArray> aesDecrypt(
    ByteArray data,
    HexString keyHex,
    HexString ivHex,
  ) async {
    final key = Key.fromBase16(keyHex);
    final iv = IV.fromBase16(ivHex);
    final encrypter = Encrypter(
      AES(key, mode: AESMode.cbc),
    );
    final decrypted = encrypter.decryptBytes(
      Encrypted(data),
      iv: iv,
    );
    return ByteArray.fromList(decrypted);
  }

  String _publicKeyToHex(RSAPublicKey publicKey) {
    final modulusHex =
        publicKey.modulus?.toByteArray().byteArrayToHexStr() ?? '';
    final exponentHex =
        publicKey.exponent?.toByteArray().byteArrayToHexStr() ?? '';
    if (modulusHex.isEmpty || exponentHex.isEmpty) {
      throw Exception('RSA public key is invalid!');
    }
    return modulusHex + exponentHex;
  }

  RSAPublicKey hexStringToRSAPublicKey(String hexString) {
    // Split the hex string into modulus and exponent
    final modulusHex =
        hexString.substring(0, 512); // First 512 characters for modulus
    final exponentHex =
        hexString.substring(512, 518); // Next 6 characters for exponent

    // Create BigInt from bytes
    final modulus = BigInt.parse(modulusHex, radix: 16);
    final exponent = BigInt.parse(exponentHex, radix: 16);

    // Create and return the RSA public key
    return RSAPublicKey(modulus, exponent);
  }

  IV _generateRandomIV() {
    return IV.fromSecureRandom(16);
  }

  @override
  ByteArray generate8ByteRandom() {
    final random = Random.secure();
    return ByteArray.fromList(List.generate(8, (_) => random.nextInt(256)));
  }

  @override
  HexString doubleSha512Hash(ByteArray input) {
    final firstHash = sha512.convert(input);
    return sha512.convert(sha512DigestToBytes(firstHash)).toString();
  }

  ByteArray sha512DigestToBytes(Digest digest) {
    return ByteArray.fromList(digest.bytes);
  }
}

typedef SignatureHex = HexString;
typedef PublicKeyHex = HexString;
