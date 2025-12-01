import 'dart:ffi';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/structs/bls_id_ffi.dart';
import 'package:blockben/secret/bls/structs/bls_public_key.dart';
import 'package:blockben/secret/bls/structs/bls_secret_key.dart';
import 'package:blockben/secret/bls/structs/bls_signature_ffi.dart';

class SecretKeyBindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  // Native function binding for blsSecretKeySerialize
  late final int Function(Pointer<Void>, int, Pointer<BlsSecretKey>)
      blsSecretKeySerialize = _lookupBlsSecretKeySerialize();
  late final int Function(Pointer<BlsSecretKey>, Pointer<Void>, int)
      blsSecretKeyDeserialize = _lookupBlsSecretKeyDeserialize();
  late final void Function(Pointer<BlsPublicKey>, Pointer<BlsSecretKey>)
      blsGetPublicKey = _lookupBlsGetPublicKey();
  late final int Function(Pointer<BlsSecretKey>) blsSecretKeySetByCSPRNG =
      _lookupBlsSecretKeySetByCSPRNG();
  late final int Function(
    Pointer<BlsSecretKey>,
    Pointer<BlsSecretKey>,
    Pointer<BlsIdFFI>,
    int,
  ) blsSecretKeyRecover = _lookupBlsSecretKeyRecover();

  late final int Function(
    Pointer<BlsSecretKey> sec,
    Pointer<BlsSecretKey> msk,
    int k,
    Pointer<BlsIdFFI> id,
  ) blsSecretKeyShare = _lookupBlsSecretKeyShare();

  late final void Function(
    Pointer<BlsSignature>,
    Pointer<BlsSecretKey>,
    Pointer<Void>,
    int,
  ) blsSign = _lookupBlsSign();

  int Function(Pointer<Void>, int, Pointer<BlsSecretKey>)
      _lookupBlsSecretKeySerialize() {
    return _lib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<Void>,
                  Int32,
                  Pointer<BlsSecretKey>,
                )>>('blsSecretKeySerialize')
        .asFunction<int Function(Pointer<Void>, int, Pointer<BlsSecretKey>)>();
  }

  int Function(Pointer<BlsSecretKey>, Pointer<Void>, int)
      _lookupBlsSecretKeyDeserialize() {
    return _lib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<BlsSecretKey>,
                  Pointer<Void>,
                  Int32,
                )>>('blsSecretKeyDeserialize')
        .asFunction<int Function(Pointer<BlsSecretKey>, Pointer<Void>, int)>();
  }

  void Function(Pointer<BlsPublicKey>, Pointer<BlsSecretKey>)
      _lookupBlsGetPublicKey() {
    return _lib
        .lookup<
            NativeFunction<
                Void Function(
                  Pointer<BlsPublicKey>,
                  Pointer<BlsSecretKey>,
                )>>('blsGetPublicKey')
        .asFunction<
            void Function(Pointer<BlsPublicKey>, Pointer<BlsSecretKey>)>();
  }

  int Function(Pointer<BlsSecretKey>) _lookupBlsSecretKeySetByCSPRNG() {
    return _lib
        .lookup<NativeFunction<Int32 Function(Pointer<BlsSecretKey>)>>(
          'blsSecretKeySetByCSPRNG',
        )
        .asFunction<int Function(Pointer<BlsSecretKey>)>();
  }

  int Function(
    Pointer<BlsSecretKey> sec,
    Pointer<BlsSecretKey> msk,
    int k,
    Pointer<BlsIdFFI> id,
  ) _lookupBlsSecretKeyShare() {
    return _lib.lookupFunction<
        Int32 Function(
          Pointer<BlsSecretKey> sec,
          Pointer<BlsSecretKey> msk,
          Int32 k,
          Pointer<BlsIdFFI> id,
        ),
        int Function(
          Pointer<BlsSecretKey> sec,
          Pointer<BlsSecretKey> msk,
          int k,
          Pointer<BlsIdFFI> id,
        )>('blsSecretKeyShare');
  }

  void Function(
    Pointer<BlsSignature>,
    Pointer<BlsSecretKey>,
    Pointer<Void>,
    int,
  ) _lookupBlsSign() {
    return _lib
        .lookup<
            NativeFunction<
                Void Function(
                  Pointer<BlsSignature>,
                  Pointer<BlsSecretKey>,
                  Pointer<Void>,
                  Int32,
                )>>('blsSign')
        .asFunction<
            void Function(
              Pointer<BlsSignature>,
              Pointer<BlsSecretKey>,
              Pointer<Void>,
              int,
            )>();
  }

  int Function(
    Pointer<BlsSecretKey>,
    Pointer<BlsSecretKey>,
    Pointer<BlsIdFFI>,
    int,
  ) _lookupBlsSecretKeyRecover() {
    return _lib.lookupFunction<
        Int32 Function(
          Pointer<BlsSecretKey>,
          Pointer<BlsSecretKey>,
          Pointer<BlsIdFFI>,
          Int32,
        ),
        int Function(
          Pointer<BlsSecretKey>,
          Pointer<BlsSecretKey>,
          Pointer<BlsIdFFI>,
          int,
        )>('blsSecretKeyRecover');
  }
}
