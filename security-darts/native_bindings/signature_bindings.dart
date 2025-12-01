import 'dart:ffi';

import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/structs/bls_id_ffi.dart';
import 'package:blockben/secret/bls/structs/bls_public_key.dart';
import 'package:blockben/secret/bls/structs/bls_signature_ffi.dart';

class SignatureBindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  int Function(Pointer<Void>, int, Pointer<BlsSignature>)
      get blsSignatureSerialize => _lookupBlsSignatureSerialize();

  int Function(
    Pointer<BlsSignature>,
    Pointer<BlsSignature>,
    Pointer<BlsIdFFI>,
    int,
  ) get blsSignatureRecover => _lookupBlsSignatureRecover();

  late final int Function(
    Pointer<BlsSignature>,
    Pointer<BlsPublicKey>,
    Pointer<Void>,
    int,
  ) blsVerify = _lookupBlsVerify();

  int Function(Pointer<Void>, int, Pointer<BlsSignature>)
      _lookupBlsSignatureSerialize() {
    return _lib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<Void>,
                  Int32,
                  Pointer<BlsSignature>,
                )>>('blsSignatureSerialize')
        .asFunction<int Function(Pointer<Void>, int, Pointer<BlsSignature>)>();
  }

  int Function(
    Pointer<BlsSignature>,
    Pointer<BlsSignature>,
    Pointer<BlsIdFFI>,
    int,
  ) _lookupBlsSignatureRecover() {
    return _lib.lookupFunction<
        Int32 Function(
          Pointer<BlsSignature>,
          Pointer<BlsSignature>,
          Pointer<BlsIdFFI>,
          Int32,
        ),
        int Function(
          Pointer<BlsSignature>,
          Pointer<BlsSignature>,
          Pointer<BlsIdFFI>,
          int,
        )>('blsSignatureRecover');
  }

  int Function(Pointer<BlsSignature>, Pointer<BlsPublicKey>, Pointer<Void>, int)
      _lookupBlsVerify() {
    return _lib.lookupFunction<
        Int32 Function(
          Pointer<BlsSignature>,
          Pointer<BlsPublicKey>,
          Pointer<Void>,
          Int32,
        ),
        int Function(
          Pointer<BlsSignature>,
          Pointer<BlsPublicKey>,
          Pointer<Void>,
          int,
        )>('blsVerify');
  }
}
