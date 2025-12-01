import 'dart:ffi';

import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/fr.dart';
import 'package:blockben/secret/mcl/mcl_bg_g1.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:ffi/ffi.dart';

class G1 {
  late final Pointer<MclBnG1> _pointer;
  Pointer<MclBnG1> get pointer => _pointer;

  G1() {
    _pointer = calloc<MclBnG1>();
  }

  ByteArray serialize() {
    const int maxBufSize = 48; // Maximum buffer size for serialization
    final Pointer<Byte> buffer = calloc(maxBufSize);

    try {
      final int size =
          nativeFunctions.g1.mclBnG1_serialize(buffer, maxBufSize, _pointer);

      if (size == 0) {
        throw Exception('mclBnG1_serialize failed');
      }

      // Convert the buffer to a ByteArray
      return ByteArray.fromList(buffer.asTypedList(size));
    } finally {
      calloc.free(buffer);
    }
  }

  G1 deserialize(ByteArray byteArray) {
    final Pointer<Byte> buffer = calloc(byteArray.length);

    try {
      // Copy input bytes into allocated buffer
      final ByteArray nativeBuffer = buffer.asTypedList(byteArray.length);
      nativeBuffer.setAll(0, byteArray);

      // Call the native deserialize function
      final int size = nativeFunctions.g1
          .mclBnG1_deserialize(_pointer, buffer, byteArray.length);

      if (size == 0) {
        throw Exception('mclBnG1_deserialize failed');
      }

      return this;
    } finally {
      calloc.free(buffer);
    }
  }

  void dispose() {
    calloc.free(_pointer);
  }

  void setHashOfWithByteArray(ByteArray s) {
    final Pointer<Byte> buffer = calloc(s.length); // Allocate buffer
    try {
      final ByteArray byteArray = buffer.asTypedList(s.length);
      byteArray.setAll(0, s);

      // Call the native mclBnG1_hashAndMapTo function
      final int result =
          nativeFunctions.g1.mclBnG1_hashAndMapTo(_pointer, buffer, s.length);

      if (result != 0) {
        throw Exception('mclBnG1_hashAndMapTo failed');
      }
    } finally {
      calloc.free(buffer);
    }
  }

  void mul(Fr rhs) {
    nativeFunctions.g1.mclBnG1_mul(_pointer, _pointer, rhs.pointer);
  }

  void clear() {
    nativeFunctions.g1.mclBnG1_clear(_pointer);
  }
}
