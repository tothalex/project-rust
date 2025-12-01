import 'dart:ffi';

import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/mcl_bn_fr.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:ffi/ffi.dart';

class Fr {

  Fr() {
    _pointer = calloc<MclBnFr>();
  }
  late final Pointer<MclBnFr> _pointer;

  Pointer<MclBnFr> get pointer => _pointer;

  ByteArray serialize() {
    const int maxBufSize = 32;
    final Pointer<Byte> buffer = calloc<Byte>(maxBufSize);

    try {
      final int size = nativeFunctions.fr
          .mclBnFr_serialize(buffer.cast<Void>(), maxBufSize, _pointer);

      if (size == 0) {
        throw Exception('Serialization failed');
      }

      return ByteArray.fromList(buffer.asTypedList(size));
    } finally {
      calloc.free(buffer);
    }
  }

  void deserialize(ByteArray byteArray) {
    final Pointer<Byte> buffer = calloc<Byte>(byteArray.length);

    try {
      final ByteArray nativeBuffer = buffer.asTypedList(byteArray.length);
      nativeBuffer.setAll(0, byteArray);

      final int size = nativeFunctions.fr
          .mclBnFr_deserialize(_pointer, buffer.cast<Void>(), byteArray.length);

      if (size == 0) {
        throw Exception('Deserialization failed');
      }
    } finally {
      calloc.free(buffer);
    }
  }

  void setByCSPRNG() {
    nativeFunctions.fr.mclBnFrSetByCSPRNG(_pointer);
  }

  void setHashOfWithByteArray(ByteArray byteArray) {
    final Pointer<Byte> buffer = calloc<Byte>(byteArray.length);

    try {
      final ByteArray nativeBuffer = buffer.asTypedList(byteArray.length);
      nativeBuffer.setAll(0, byteArray);

      final int result = nativeFunctions.fr
          .mclBnFr_setHashOf(_pointer, buffer.cast<Void>(), byteArray.length);

      if (result != 0) {
        throw Exception('mclBnFr_setHashOf failed with error code: $result');
      }
    } finally {
      calloc.free(buffer);
    }
  }

  void add(Fr y) {
    nativeFunctions.fr.mclBnFr_add(_pointer, _pointer, y.pointer);
  }

  void clear() {
    nativeFunctions.fr.mclBnFr_clear(_pointer);
  }

  void div(Fr rhs) {
    nativeFunctions.fr.mclBnFr_div(_pointer, _pointer, rhs.pointer);
  }

  void sub(Fr y) {
    nativeFunctions.fr.mclBnFr_sub(_pointer, _pointer, y.pointer);
  }
}
