
import 'package:flutter_keychain_plus/flutter_keychain_plus.dart';

abstract class SecureStorage {
  Future<void> delete(String keyAlias);
  Future<String?> get(String keyAlias);
  Future<void> save({required String key, required String value});
  Future<void> clearAllSecureData();
}

class SecureStorageImpl implements SecureStorage {
  @override
  Future<void> delete(String keyAlias) async {
    await FlutterKeychainPlus.remove(key: keyAlias);
  }

  @override
  Future<String?> get(String keyAlias) async {
    return await FlutterKeychainPlus.get(key: keyAlias);
  }

  @override
  Future<void> save({required String key, required String value}) async {
    await FlutterKeychainPlus.put(key: key, value: value);
  }

  @override
  Future<void> clearAllSecureData() async {
    await FlutterKeychainPlus.clear();
  }
}
