import 'dart:ffi';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/mcl_bn_fr.dart';
import 'package:blockben/secret/mcl/mcl_bn_g2.dart';

class G2Bindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  // Lazy initialization of native functions for G2
  late final int Function(Pointer<Byte>, int, Pointer<MclBnG2>) mclBnG2_serialize = _lookupMclBnG2Serialize();
  late final int Function(Pointer<MclBnG2>, Pointer<Byte>, int) mclBnG2_deserialize = _lookupMclBnG2Deserialize();
  late final void Function(Pointer<MclBnG2>, Pointer<MclBnG2>, Pointer<MclBnFr>) mclBnG2_mul = _lookupMclBnG2Mul();
  late final void Function(Pointer<MclBnG2>) mclBnG2_clear = _lookupMclBnG2Clear();

  // Private methods to lookup each function lazily
  int Function(Pointer<Byte>, int, Pointer<MclBnG2>) _lookupMclBnG2Serialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<Byte>, IntPtr, Pointer<MclBnG2>)>>('mclBnG2_serialize')
        .asFunction<int Function(Pointer<Byte>, int, Pointer<MclBnG2>)>();
  }

  int Function(Pointer<MclBnG2>, Pointer<Byte>, int) _lookupMclBnG2Deserialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<MclBnG2>, Pointer<Byte>, IntPtr)>>('mclBnG2_deserialize')
        .asFunction<int Function(Pointer<MclBnG2>, Pointer<Byte>, int)>();
  }

  void Function(Pointer<MclBnG2>, Pointer<MclBnG2>, Pointer<MclBnFr>) _lookupMclBnG2Mul() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnG2>, Pointer<MclBnG2>, Pointer<MclBnFr>)>>('mclBnG2_mul')
        .asFunction<void Function(Pointer<MclBnG2>, Pointer<MclBnG2>, Pointer<MclBnFr>)>();
  }

  void Function(Pointer<MclBnG2>) _lookupMclBnG2Clear() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnG2>)>>('mclBnG2_clear')
        .asFunction<void Function(Pointer<MclBnG2>)>();
  }
}
