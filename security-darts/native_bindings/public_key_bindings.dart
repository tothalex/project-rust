import 'dart:ffi';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/structs/bls_id_ffi.dart';
import 'package:blockben/secret/bls/structs/bls_public_key.dart';

class PublicKeyBindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  // Native function bindings
  late final int Function(Pointer<Void>, int, Pointer<BlsPublicKey>)
      blsPublicKeySerialize = _lookupBlsPublicKeySerialize();
  late final int Function(Pointer<BlsPublicKey>, Pointer<Void>, int)
      blsPublicKeyDeserialize = _lookupBlsPublicKeyDeserialize();
  late final int Function(
    Pointer<BlsPublicKey>,
    Pointer<BlsPublicKey>,
    Pointer<BlsIdFFI>,
    int,
  ) blsPublicKeyRecover = _lookupBlsPublicKeyRecover();

  late final int Function(
    Pointer<BlsPublicKey>,
    Pointer<BlsPublicKey>,
    int,
    Pointer<BlsIdFFI>,
  ) blsPublicKeyShare = _lookupBlsPublicKeyShare();

  late final int Function(Pointer<BlsPublicKey>, Pointer<BlsPublicKey>)
      blsPublicKeyIsEqual = _lookupBlsPublicKeyIsEqual();

  // Private methods to lookup each function lazily
  int Function(Pointer<Void>, int, Pointer<BlsPublicKey>)
      _lookupBlsPublicKeySerialize() {
    return _lib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<Void>,
                  Int32,
                  Pointer<BlsPublicKey>,
                )>>('blsPublicKeySerialize')
        .asFunction<int Function(Pointer<Void>, int, Pointer<BlsPublicKey>)>();
  }

  int Function(Pointer<BlsPublicKey>, Pointer<Void>, int)
      _lookupBlsPublicKeyDeserialize() {
    return _lib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<BlsPublicKey>,
                  Pointer<Void>,
                  Int32,
                )>>('blsPublicKeyDeserialize')
        .asFunction<int Function(Pointer<BlsPublicKey>, Pointer<Void>, int)>();
  }

  int Function(
    Pointer<BlsPublicKey>,
    Pointer<BlsPublicKey>,
    int,
    Pointer<BlsIdFFI>,
  ) _lookupBlsPublicKeyShare() {
    return _lib.lookupFunction<
        Int32 Function(
          Pointer<BlsPublicKey>,
          Pointer<BlsPublicKey>,
          Int32,
          Pointer<BlsIdFFI>,
        ),
        int Function(
          Pointer<BlsPublicKey>,
          Pointer<BlsPublicKey>,
          int,
          Pointer<BlsIdFFI>,
        )>('blsPublicKeyShare');
  }

  int Function(
    Pointer<BlsPublicKey>,
    Pointer<BlsPublicKey>,
    Pointer<BlsIdFFI>,
    int,
  ) _lookupBlsPublicKeyRecover() {
    return _lib.lookupFunction<
        Int32 Function(
          Pointer<BlsPublicKey>,
          Pointer<BlsPublicKey>,
          Pointer<BlsIdFFI>,
          Int32,
        ),
        int Function(
          Pointer<BlsPublicKey>,
          Pointer<BlsPublicKey>,
          Pointer<BlsIdFFI>,
          int,
        )>('blsPublicKeyRecover');
  }

  int Function(Pointer<BlsPublicKey>, Pointer<BlsPublicKey>)
      _lookupBlsPublicKeyIsEqual() {
    return _lib.lookupFunction<
        Int32 Function(Pointer<BlsPublicKey>, Pointer<BlsPublicKey>),
        int Function(Pointer<BlsPublicKey>, Pointer<BlsPublicKey>)>(
      'blsPublicKeyIsEqual',
    );
  }
}
