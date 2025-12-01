import 'dart:ffi';

import 'package:blockben/secret/bls/signature.dart';
import 'package:blockben/secret/bls/structs/bls_signature_ffi.dart';
import 'package:ffi/ffi.dart';

class SignatureVec {
  late final Pointer<BlsSignature> _pointer;
  late final int _length;

  SignatureVec(List<Signature> list) {
    _length = list.length;
    _pointer = calloc<BlsSignature>(length);
    for (int i = 0; i < _length; i++) {
      _pointer[i].v = list[i].pointer.ref.v;
    }
  }

  Pointer<BlsSignature> get pointer => _pointer;

  int get length => _length;

  // Access operator to access individual keys
  BlsSignature operator [](int index) => _pointer[index];

  // Access operator to set individual keys
  void operator []=(int index, BlsSignature signature) {
    _pointer[index] = signature;
  }

  void dispose() {
    calloc.free(_pointer);
  }
}
