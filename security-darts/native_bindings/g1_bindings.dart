import 'dart:ffi';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/mcl_bg_g1.dart';
import 'package:blockben/secret/mcl/mcl_bn_fr.dart';

class G1Bindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  // Lazy initialization of native functions for G1
  late final int Function(Pointer<Byte>, int, Pointer<MclBnG1>,) mclBnG1_serialize = _lookupMclBnG1Serialize();
  late final int Function(Pointer<MclBnG1>, Pointer<Byte>, int) mclBnG1_deserialize = _lookupMclBnG1Deserialize();
  late final int Function(Pointer<MclBnG1>, Pointer<Byte>, int) mclBnG1_hashAndMapTo = _lookupMclBnG1HashAndMapTo();
  late final void Function(Pointer<MclBnG1>, Pointer<MclBnG1>, Pointer<MclBnFr>) mclBnG1_mul = _lookupMclBnG1Mul();
  late final void Function(Pointer<MclBnG1>) mclBnG1_clear = _lookupMclBnG1Clear();

  // Private methods to lookup each function lazily
  int Function(Pointer<Byte>, int, Pointer<MclBnG1>) _lookupMclBnG1Serialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<Byte>, IntPtr, Pointer<MclBnG1>)>>('mclBnG1_serialize')
        .asFunction<int Function(Pointer<Byte>, int, Pointer<MclBnG1>)>();
  }

  int Function(Pointer<MclBnG1>, Pointer<Byte>, int) _lookupMclBnG1Deserialize() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<MclBnG1>, Pointer<Byte>, IntPtr)>>('mclBnG1_deserialize')
        .asFunction<int Function(Pointer<MclBnG1>, Pointer<Byte>, int)>();
  }

  int Function(Pointer<MclBnG1>, Pointer<Byte>, int) _lookupMclBnG1HashAndMapTo() {
    return _lib
        .lookup<NativeFunction<IntPtr Function(Pointer<MclBnG1>, Pointer<Byte>, IntPtr)>>('mclBnG1_hashAndMapTo')
        .asFunction<int Function(Pointer<MclBnG1>, Pointer<Byte>, int)>();
  }

  void Function(Pointer<MclBnG1>, Pointer<MclBnG1>, Pointer<MclBnFr>) _lookupMclBnG1Mul() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnG1>, Pointer<MclBnG1>, Pointer<MclBnFr>)>>('mclBnG1_mul')
        .asFunction<void Function(Pointer<MclBnG1>, Pointer<MclBnG1>, Pointer<MclBnFr>)>();
  }

  void Function(Pointer<MclBnG1>) _lookupMclBnG1Clear() {
    return _lib
        .lookup<NativeFunction<Void Function(Pointer<MclBnG1>)>>('mclBnG1_clear')
        .asFunction<void Function(Pointer<MclBnG1>)>();
  }
}
