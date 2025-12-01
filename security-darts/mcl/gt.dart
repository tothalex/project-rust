import 'dart:ffi';

import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/g1.dart';
import 'package:blockben/secret/mcl/g2.dart';
import 'package:blockben/secret/mcl/mcl_bn_gt.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:ffi/ffi.dart';

class GT {

  GT() {
    _pointer = calloc<MclBnGT>();
  }
  late final Pointer<MclBnGT> _pointer;

  Pointer<MclBnGT> get pointer => _pointer;

  ByteArray serialize() {
    const int maxBufSize = 576;

    // Allocate memory for the buffer
    final Pointer<Byte> buffer = calloc(maxBufSize);

    try {
      // Call the native mclBnGT_serialize function
      final int size = nativeFunctions.gt
          .mclBnGT_serialize(buffer.cast<Void>(), maxBufSize, _pointer);

      if (size == 0) {
        throw Exception('Serialization failed');
      }

      // Convert the buffer to a ButeArray and return it
      return ByteArray.fromList(buffer.asTypedList(size));
    } finally {
      // Free the allocated buffer
      calloc.free(buffer);
    }
  }

  void deserialize(ByteArray byteArray) {
    final Pointer<Byte> buffer = calloc(byteArray.length);
    buffer.asTypedList(byteArray.length).setAll(0, byteArray);

    try {
      final int size = nativeFunctions.gt.mclBnGT_deserialize(
        _pointer,
        buffer.cast<Void>(),
        byteArray.length,
      );

      if (size == 0) {
        throw Exception('Deserialization failed');
      }
    } finally {
      calloc.free(buffer);
    }
  }

  void pairing(G1 g1, G2 g2) {
    nativeFunctions.gt.mclBn_pairing(_pointer, g1.pointer, g2.pointer);
  }

  void mul(GT rhs) {
    nativeFunctions.gt.mclBnGT_mul(_pointer, _pointer, rhs.pointer);
  }

  bool equals(GT other) {
    return nativeFunctions.gt.mclBnGT_isEqual(_pointer, other.pointer) != 0;
  }

  void dispose() {
    calloc.free(_pointer);
  }

  void clear() {
    nativeFunctions.gt.mclBnGT_clear(_pointer);
  }
}
