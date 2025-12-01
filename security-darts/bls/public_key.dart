import 'dart:ffi';

import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/bls_id.dart';
import 'package:blockben/secret/bls/id_vec.dart';
import 'package:blockben/secret/bls/public_key_vec.dart';
import 'package:blockben/secret/bls/structs/bls_public_key.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/g1.dart';
import 'package:blockben/secret/mcl/g2.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';

class PublicKey {
  PublicKey() {
    _pointer = calloc<BlsPublicKey>();
  }

  late final Pointer<BlsPublicKey> _pointer;

  Pointer<BlsPublicKey> get pointer => _pointer;

  String toHex() => serialize().byteArrayToHexStr();

  void deserialize(ByteArray byteArray) {
    final bufPointer = calloc<Byte>(byteArray.length);
    try {
      final buf = bufPointer.asTypedList(byteArray.length);
      buf.setAll(0, byteArray);
      nativeFunctions.pk.blsPublicKeyDeserialize(
        _pointer,
        bufPointer.cast(),
        byteArray.length,
      );
    } on Exception catch (e) {
      debugPrint('Error in deserialize: $e');
    } finally {
      calloc.free(bufPointer);
    }
  }

  ByteArray serialize() {
    const maxSize = 96;
    final bufPointer = calloc<Byte>(maxSize);

    try {
      final result = nativeFunctions.pk
          .blsPublicKeySerialize(bufPointer.cast<Void>(), maxSize, _pointer);

      if (result <= 0) {
        throw Exception('blsPublicKeySerialize failed with code: $result');
      }

      final bufSize = result;
      final serializedList = bufPointer.asTypedList(bufSize);

      return ByteArray.fromList(serializedList);
    } catch (e) {
      debugPrint('Error in serialize: $e');
      return ByteArray(0); // Return an empty list on error
    } finally {
      calloc.free(bufPointer); // Free the buffer to avoid memory leaks
    }
  }

  G2 toG2() {
    if (BLS.isDefinedBLS_ETH()) {
      throw Exception('BLS initialized: G1 is Signature; G2 is PublicKey');
    }
    final g2 = G2();
    final serialized = serialize();
    g2.deserialize(serialized);
    return g2;
  }

  G1 toG1() {
    if (!BLS.isDefinedBLS_ETH()) {
      throw Exception('BLS initialized: G1 is Signature; G2 is PublicKey');
    }
    final g1 = G1();
    final serialized = serialize();
    g1.deserialize(serialized);
    return g1;
  }

  void clear() {
    final sizeInBytes = sizeOf<BlsPublicKey>();
    final zeroData = calloc<Byte>(sizeInBytes);
    pointer
        .cast<Byte>()
        .asTypedList(sizeInBytes)
        .setAll(0, zeroData.asTypedList(sizeInBytes));
    calloc.free(zeroData);
    calloc.free(_pointer);
  }

  void share(PublicKeyVec publicKeyVec, BlsId blsId) {
    nativeFunctions.pk.blsPublicKeyShare(
      pointer,
      publicKeyVec.pointer,
      publicKeyVec.length,
      blsId.pointer,
    );
  }

  void recover(PublicKeyVec publicKeyVec, IdVec idVec) {
    nativeFunctions.pk.blsPublicKeyRecover(
      pointer,
      publicKeyVec.pointer,
      idVec.pointer,
      idVec.length,
    );
  }

  bool equals(PublicKey rhs) {
    return nativeFunctions.pk.blsPublicKeyIsEqual(pointer, rhs.pointer) == 1;
  }
  
}
