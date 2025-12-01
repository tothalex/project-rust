import 'dart:ffi';

import 'package:blockben/secret/bls/structs/bls_id_ffi.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:ffi/ffi.dart';

class BlsId {
  BlsId() {
    _pointer = calloc<BlsIdFFI>();
  }
  late final Pointer<BlsIdFFI> _pointer;
  Pointer<BlsIdFFI> get pointer => _pointer;

  // Convert BlsId to a hex string
  String toHex() => serialize().byteArrayToHexStr();

  // Deserialize function for BlsId
  void deserialize(ByteArray byteArray) {
    final bufPointer = calloc<Byte>(byteArray.length);

    try {
      final buf = bufPointer.asTypedList(byteArray.length);
      buf.setAll(0, byteArray);

      nativeFunctions.blsId
          .blsIdDeserialize(_pointer, bufPointer.cast(), byteArray.length);
    } finally {
      calloc.free(bufPointer);
    }
  }

  // Serialize function for BlsId
  ByteArray serialize() {
    const maxSize = 32;
    final bufPointer = calloc<Byte>(maxSize);

    try {
      final result = nativeFunctions.blsId
          .blsIdSerialize(bufPointer.cast(), maxSize, _pointer);

      final serializedList = bufPointer.asTypedList(result);
      return ByteArray.fromList(serializedList);
    } finally {
      calloc.free(bufPointer);
    }
  }

  void dispose() {
    calloc.free(_pointer);
  }

  bool equals(BlsId rhs) {
    return nativeFunctions.blsId.blsIdIsEqual(pointer, rhs.pointer) == 1;
  }
}
