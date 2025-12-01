import 'dart:ffi';

import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/structs/bls_public_key.dart';
import 'package:ffi/ffi.dart';

class PublicKeyVec {
  late final Pointer<BlsPublicKey> _pointer;
  late final int _length;

  PublicKeyVec(List<PublicKey> list) {
    _length = list.length;
    _pointer = calloc<BlsPublicKey>(length);
    for (int i = 0; i < _length; i++) {
      _pointer[i].v = list[i].pointer.ref.v;
    }
  }

  Pointer<BlsPublicKey> get pointer => _pointer;
  int get length => _length;

  // Access operator to access individual keys
  BlsPublicKey operator [](int index) => _pointer[index];

  // Access operator to set individual keys
  void operator []=(int index, BlsPublicKey key) {
    _pointer[index] = key;
  }

  void dispose() {
    calloc.free(_pointer);
  }
}
