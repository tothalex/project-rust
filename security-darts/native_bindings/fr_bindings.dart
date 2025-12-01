import 'dart:ffi';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/mcl/mcl_bn_fr.dart';

class FrBindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  // Native function binding
  late final int Function(Pointer<Void>, int, Pointer<MclBnFr>) mclBnFr_serialize = _lookupMclBnFrSerialize();
  late final int Function(Pointer<MclBnFr>, Pointer<Void>, int) mclBnFr_deserialize = _lookupMclBnFrDeserialize();
  late final int Function(Pointer<MclBnFr>, Pointer<Void>, int) mclBnFr_setHashOf = _lookupMclBnFrSetHashOf();
  late final int Function(Pointer<MclBnFr>) mclBnFrSetByCSPRNG = _lookupMclBnFrSetByCSPRNG();
  late final void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>) mclBnFr_add = _lookupMclBnFrAdd();
  late final void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>) mclBnFr_sub = _lookupMclBnFrSub();
  late final void Function(Pointer<MclBnFr>) mclBnFr_clear = _lookupMclBnFrClear();
  late final void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>) mclBnFr_div = _lookupMclBnFrDiv();

  // Private methods to lookup each function lazily
  int Function(Pointer<Void>, int, Pointer<MclBnFr>) _lookupMclBnFrSerialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<Void>, IntPtr, Pointer<MclBnFr>)>>('mclBnFr_serialize')
        .asFunction<int Function(Pointer<Void>, int, Pointer<MclBnFr>)>();
  }

  int Function(Pointer<MclBnFr>, Pointer<Void>, int) _lookupMclBnFrDeserialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<MclBnFr>, Pointer<Void>, IntPtr)>>('mclBnFr_deserialize')
        .asFunction<int Function(Pointer<MclBnFr>, Pointer<Void>, int)>();
  }

  int Function(Pointer<MclBnFr>, Pointer<Void>, int) _lookupMclBnFrSetHashOf() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<MclBnFr>, Pointer<Void>, IntPtr)>>('mclBnFr_setHashOf')
        .asFunction<int Function(Pointer<MclBnFr>, Pointer<Void>, int)>();
  }

  int Function(Pointer<MclBnFr>) _lookupMclBnFrSetByCSPRNG() {
    return _lib
        .lookup<NativeFunction<Int32 Function(Pointer<MclBnFr>)>>('mclBnFr_setByCSPRNG')
        .asFunction<int Function(Pointer<MclBnFr>)>();
  }

  void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>) _lookupMclBnFrAdd() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>)>>('mclBnFr_add')
        .asFunction<void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>)>();
  }

  void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>) _lookupMclBnFrSub() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>)>>('mclBnFr_sub')
        .asFunction<void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>)>();
  }

  void Function(Pointer<MclBnFr>) _lookupMclBnFrClear() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnFr>)>>('mclBnFr_clear')
        .asFunction<void Function(Pointer<MclBnFr>)>();
  }

  void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>) _lookupMclBnFrDiv() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>)>>('mclBnFr_div')
        .asFunction<void Function(Pointer<MclBnFr>, Pointer<MclBnFr>, Pointer<MclBnFr>)>();
  }
}
