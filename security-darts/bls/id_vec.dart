import 'dart:ffi';

import 'package:blockben/secret/bls/bls_id.dart';
import 'package:blockben/secret/bls/structs/bls_id_ffi.dart';
import 'package:ffi/ffi.dart';

class IdVec {
  late final Pointer<BlsIdFFI> _pointer;
  late final int _length;

  IdVec(List<BlsId> list) {
    _length = list.length;
    _pointer = calloc<BlsIdFFI>(length);
    for (int i = 0; i < _length; i++) {
      _pointer[i].v = list[i].pointer.ref.v;
    }
  }

  Pointer<BlsIdFFI> get pointer => _pointer;
  int get length => _length;

  // Access operator to access individual keys
  BlsIdFFI operator [](int index) => _pointer[index];

  // Access operator to set individual keys
  void operator []=(int index, BlsIdFFI key) {
    _pointer[index] = key;
  }

  void dispose() {
    calloc.free(_pointer);
  }
}
