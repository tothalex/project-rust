import 'dart:math';

import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/crypto/secure_storage.dart';
import 'package:blockben/services/shared_prefs_manager.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';

abstract class KeystoreProvider {
  AsymmetricKeyPair<PublicKey, PrivateKey> generateRSAKeyPair(String keyAlias);
  Future<IV?> getIV(String ivAlias);
  Future<void> saveIV(String ivAlias, IV iv);
  Future<Key> getOrCreateAES256Key(String keyAlias);
  Future<Key?> getAES256Key(String alias);
}

class KeystoreProviderImpl implements KeystoreProvider {
  KeystoreProviderImpl(this.sharedPrefsManager, this.secureStorage);
  SharedPrefsManager sharedPrefsManager;
  SecureStorage secureStorage;

  @override
  AsymmetricKeyPair<PublicKey, PrivateKey> generateRSAKeyPair(
    String keyAlias,
  ) {
    final keyParams = RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 12);
    final secureRandom = _getSecureRandom();

    final params = ParametersWithRandom(keyParams, secureRandom);
    final keyGenerator = RSAKeyGenerator();
    keyGenerator.init(params);

    return keyGenerator.generateKeyPair();
  }

  // Function to generate a secure FortunaRandom instance
  FortunaRandom _getSecureRandom() {
    final secureRandom = FortunaRandom();
    final random = Random.secure();

    // Generate 32 bytes (256 bits) of secure randomness
    final seed =
        ByteArray.fromList(List<int>.generate(32, (_) => random.nextInt(256)));

    // Seed the FortunaRandom instance with this secure randomness
    secureRandom.seed(KeyParameter(seed));

    return secureRandom;
  }

  @override
  Future<IV?> getIV(String ivAlias) async {
    final ivHex = await sharedPrefsManager.getString(key: _getIvKey(ivAlias));
    if (ivHex != null) {
      return IV.fromBase16(ivHex);
    }
    return null;
  }

  @override
  Future<void> saveIV(String ivAlias, IV iv) async {
    await sharedPrefsManager.setString(
      key: _getIvKey(ivAlias),
      value: iv.base16,
    );
  }

  static const ivPostfix = '_IV';

  String _getIvKey(String ivAlias) => '$ivAlias$ivPostfix';

  @override
  Future<Key> getOrCreateAES256Key(String alias) async {
    // Attempt to retrieve the existing key
    final existingKey = await getAES256Key(alias);
    if (existingKey != null) {
      return existingKey; // Return the existing key
    }

    // Generate new key
    final key = Key.fromSecureRandom(32); // 32 bytes for AES-256
    secureStorage.save(key: alias, value: key.base16);
    return key; // Return the newly generated key
  }

  @override
  Future<Key?> getAES256Key(String alias) async {
    final hexKey = await secureStorage.get(alias);
    if (hexKey == null) return null;
    return Key.fromBase16(hexKey);
  }
}
