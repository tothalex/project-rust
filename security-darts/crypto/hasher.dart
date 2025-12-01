import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/pin/pin_manager.dart';
import 'package:crypto/crypto.dart';

abstract class Hasher {
  ByteArray sha512Hash(String input);
}

class HasherImpl extends Hasher {
  @override
  ByteArray sha512Hash(String input) {
    final bytes = input.toByteArray();
    final digest = sha512.convert(bytes);
    return ByteArray.fromList(digest.bytes);
  }
}
