import 'dart:ffi';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/structs/bls_id_ffi.dart';

class BlsIdBindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  late final int Function(
    Pointer<Void> buf,
    int maxBufSize,
    Pointer<BlsIdFFI> id,
  ) blsIdSerialize = _lookupBlsIdSerialize();

  late final int Function(Pointer<BlsIdFFI> id, Pointer<Void> buf, int bufSize)
      blsIdDeserialize = _lookupBlsIdDeserialize();

  late final int Function(Pointer<BlsIdFFI>) blsIdByCSPRNG =
      _lookupBlsIdSetByCSPRNG();

  late final int Function(Pointer<BlsIdFFI> lhs, Pointer<BlsIdFFI> rhs)
      blsIdIsEqual = _lookupBlsIdIsEqual();

  // Private method to lookup the blsIdSerialize function
  int Function(Pointer<Void> buf, int maxBufSize, Pointer<BlsIdFFI> id)
      _lookupBlsIdSerialize() {
    return _lib.lookupFunction<
        Int32 Function(
          Pointer<Void> buf,
          Int32 maxBufSize,
          Pointer<BlsIdFFI> id,
        ),
        int Function(
          Pointer<Void> buf,
          int maxBufSize,
          Pointer<BlsIdFFI> id,
        )>('blsIdSerialize');
  }

  // Private method to lookup the blsIdDeserialize function
  int Function(Pointer<BlsIdFFI> id, Pointer<Void> buf, int bufSize)
      _lookupBlsIdDeserialize() {
    return _lib.lookupFunction<
        Int32 Function(Pointer<BlsIdFFI> id, Pointer<Void> buf, Int32 bufSize),
        int Function(
          Pointer<BlsIdFFI> id,
          Pointer<Void> buf,
          int bufSize,
        )>('blsIdDeserialize');
  }

  int Function(Pointer<BlsIdFFI>) _lookupBlsIdSetByCSPRNG() {
    return _lib
        .lookup<NativeFunction<Int32 Function(Pointer<BlsIdFFI>)>>(
          'blsSecretKeySetByCSPRNG',
        )
        .asFunction<int Function(Pointer<BlsIdFFI>)>();
  }

  int Function(Pointer<BlsIdFFI> lhs, Pointer<BlsIdFFI> rhs)
      _lookupBlsIdIsEqual() {
    return _lib.lookupFunction<
        Int32 Function(Pointer<BlsIdFFI> lhs, Pointer<BlsIdFFI> rhs),
        int Function(
          Pointer<BlsIdFFI> lhs,
          Pointer<BlsIdFFI> rhs,
        )>('blsIdIsEqual');
  }
}
