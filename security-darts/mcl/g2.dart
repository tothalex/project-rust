import 'dart:ffi';

import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/fr.dart';
import 'package:blockben/secret/mcl/mcl_bn_g2.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:ffi/ffi.dart';

class G2 {

  G2() {
    _pointer = calloc<MclBnG2>(); // Allocate memory for MclBnG2
  }
  late final Pointer<MclBnG2> _pointer;

  Pointer<MclBnG2> get pointer => _pointer;

  ByteArray serialize() {
    const int maxBufSize = 96; // Maximum buffer size for serialization
    final Pointer<Byte> buffer = calloc(maxBufSize); // Allocate buffer

    try {
      final int size = nativeFunctions.g2
          .mclBnG2_serialize(buffer.cast(), maxBufSize, _pointer);

      if (size == 0) {
        throw Exception('mclBnG2_serialize failed');
      }

      return ByteArray.fromList(buffer.asTypedList(size));
    } finally {
      calloc.free(buffer);
    }
  }

  void deserialize(ByteArray byteArray) {
    // Allocate buffer for the byte data
    final Pointer<Byte> buffer = calloc(byteArray.length);

    try {
      // Copy the bytes into the allocated buffer
      buffer.asTypedList(byteArray.length).setAll(0, byteArray);

      // Call the native deserialize function to modify the current _pointer
      final int size = nativeFunctions.g2.mclBnG2_deserialize(
        _pointer,
        buffer.cast<Byte>(),
        byteArray.length,
      );

      if (size == 0) {
        throw Exception('Deserialization failed');
      }
    } finally {
      calloc.free(buffer);
    }
  }

  // Multiply the G2 object by a scalar (Fr)
  void mul(Fr rhs) {
    nativeFunctions.g2.mclBnG2_mul(_pointer, _pointer, rhs.pointer);
  }

  // Clear the G2 object
  void clear() {
    nativeFunctions.g2.mclBnG2_clear(_pointer);
  }

  // Dispose of the allocated memory
  void dispose() {
    calloc.free(_pointer);
  }
}
