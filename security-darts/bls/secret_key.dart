import 'dart:ffi';

import 'package:blockben/secret/bls/bls_id.dart';
import 'package:blockben/secret/bls/id_vec.dart';
import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/secret_key_vec.dart';
import 'package:blockben/secret/bls/signature.dart';
import 'package:blockben/secret/bls/structs/bls_secret_key.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/fr.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:blockben/secret/pvsh/hiver.dart';
import 'package:ffi/ffi.dart';

typedef SecretKeyHex = HexString;

class SecretKey {
  SecretKey() {
    _pointer = calloc<BlsSecretKey>();
  }
  late final Pointer<BlsSecretKey> _pointer;

  Pointer<BlsSecretKey> get pointer => _pointer;

  String toHex() {
    return serialize().byteArrayToHexStr();
  }

  void deserialize(ByteArray byteArray) {
    final bufPointer = calloc<Byte>(byteArray.length);

    try {
      final buf = bufPointer.asTypedList(byteArray.length);
      buf.setAll(0, byteArray);

      final size = nativeFunctions.sk.blsSecretKeyDeserialize(
        _pointer,
        bufPointer.cast(),
        byteArray.length,
      );
      // byteArray.length > 1 is because empty string cant be encrypted
      // We are using a 00 instead, which is a 1 long byte array.
      if (size == 0 && byteArray.length > 1) {
        throw Exception('Deserialization failed for ${byteArray.byteArrayToHexStr()}');
      }
    } finally {
      calloc.free(bufPointer);
    }
  }

  ByteArray serialize() {
    int maxSize = 32;
    Pointer<Byte> bufPointer = calloc<Byte>(maxSize);

    try {
      int serializedSize = nativeFunctions.sk
          .blsSecretKeySerialize(bufPointer.cast(), maxSize, _pointer);

      if (serializedSize > maxSize) {
        // Reallocate the buffer if initial size was too small
        calloc.free(bufPointer);
        maxSize = serializedSize; // Use the new size
        bufPointer = calloc(maxSize);

        // Serialize again with the correct buffer size
        serializedSize = nativeFunctions.sk
            .blsSecretKeySerialize(bufPointer.cast(), maxSize, _pointer);
        if (serializedSize != maxSize) {
          throw Exception('Serialization failed');
        }
      }

      return ByteArray.fromList(bufPointer.asTypedList(serializedSize));
    } finally {
      calloc.free(bufPointer);
    }
  }

  void setByCSPRNG() {
    nativeFunctions.sk.blsSecretKeySetByCSPRNG(_pointer);
  }

  Fr toFr() => Fr()..deserialize(serialize());

  PublicKey get publicKey {
    final publicKey = PublicKey();
    nativeFunctions.sk.blsGetPublicKey(publicKey.pointer, _pointer);

    return publicKey;
  }

  void share(SecretKeyVec secretKeyVec, BlsId id) {
    nativeFunctions.sk.blsSecretKeyShare(
      pointer,
      secretKeyVec.pointer,
      secretKeyVec.length,
      id.pointer,
    );
  }

  void clear() {
    final sizeInBytes = sizeOf<BlsSecretKey>();
    final zeroData = calloc<Uint8>(sizeInBytes);
    pointer
        .cast<Uint8>()
        .asTypedList(sizeInBytes)
        .setAll(0, zeroData.asTypedList(sizeInBytes));
    calloc.free(zeroData);
    calloc.free(pointer);
  }

  Signature sign(ByteArray hash) {
    final signature = Signature();
    final pointerForHash =
        replicateByteArray(hash); // Hash replikálása és pointer megszerzése
    final lengthOfHash = hash.length; // Hash byte tömb hossza

    nativeFunctions.sk.blsSign(
      signature.pointer,
      pointer,
      pointerForHash.cast(),
      lengthOfHash,
    );
    return signature;
  }

  Pointer<Uint8> replicateByteArray(ByteArray hash) {
    final pointerForHash = calloc<Byte>(
      hash.length,
    );
    final typedData = pointerForHash.asTypedList(hash.length);
    typedData.setAll(0, hash);
    return pointerForHash;
  }

  void recover(SecretKeyVec secretKeyVec, IdVec idVec) {
    nativeFunctions.sk.blsSecretKeyRecover(
      pointer,
      secretKeyVec.pointer,
      idVec.pointer,
      idVec.length,
    );
  }
}
