import 'dart:ffi';

import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/mcl/mcl_bg_g1.dart';
import 'package:blockben/secret/mcl/mcl_bn_g2.dart';
import 'package:blockben/secret/mcl/mcl_bn_gt.dart';

class GTBindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  // Lazy initialization of native functions for GT
  late final int Function(Pointer<Void>, int, Pointer<MclBnGT>) mclBnGT_serialize = _lookupMclBnGTSerialize();
  late final int Function(Pointer<MclBnGT>, Pointer<Void>, int) mclBnGT_deserialize = _lookupMclBnGTDeserialize();
  late final void Function(Pointer<MclBnGT>) mclBnGT_clear = _lookupMclBnGTClear();
  late final void Function(Pointer<MclBnGT>, Pointer<MclBnGT>, Pointer<MclBnGT>) mclBnGT_mul = _lookupMclBnGTMul();
  late final int Function(Pointer<MclBnGT>, Pointer<MclBnGT>) mclBnGT_isEqual = _lookupMclBnGTIsEqual();
  late final void Function(Pointer<MclBnGT>, Pointer<MclBnG1>, Pointer<MclBnG2>) mclBn_pairing = _lookupMclBnPairing();

  // Private methods to lookup each function lazily
  int Function(Pointer<Void>, int, Pointer<MclBnGT>) _lookupMclBnGTSerialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<Void>, IntPtr, Pointer<MclBnGT>)>>('mclBnGT_serialize')
        .asFunction<int Function(Pointer<Void>, int, Pointer<MclBnGT>)>();
  }

  int Function(Pointer<MclBnGT>, Pointer<Void>, int) _lookupMclBnGTDeserialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<MclBnGT>, Pointer<Void>, IntPtr)>>('mclBnGT_deserialize')
        .asFunction<int Function(Pointer<MclBnGT>, Pointer<Void>, int)>();
  }

  void Function(Pointer<MclBnGT>) _lookupMclBnGTClear() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnGT>)>>('mclBnGT_clear')
        .asFunction<void Function(Pointer<MclBnGT>)>();
  }

  void Function(Pointer<MclBnGT>, Pointer<MclBnGT>, Pointer<MclBnGT>) _lookupMclBnGTMul() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnGT>, Pointer<MclBnGT>, Pointer<MclBnGT>)>>('mclBnGT_mul')
        .asFunction<void Function(Pointer<MclBnGT>, Pointer<MclBnGT>, Pointer<MclBnGT>)>();
  }

  int Function(Pointer<MclBnGT>, Pointer<MclBnGT>) _lookupMclBnGTIsEqual() {
    return _lib
        .lookup<NativeFunction<Int32 Function(Pointer<MclBnGT>, Pointer<MclBnGT>)>>('mclBnGT_isEqual')
        .asFunction<int Function(Pointer<MclBnGT>, Pointer<MclBnGT>)>();
  }

  void Function(Pointer<MclBnGT>, Pointer<MclBnG1>, Pointer<MclBnG2>) _lookupMclBnPairing() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnGT>, Pointer<MclBnG1>, Pointer<MclBnG2>)>>('mclBn_pairing')
        .asFunction<void Function(Pointer<MclBnGT>, Pointer<MclBnG1>, Pointer<MclBnG2>)>();
  }
}
