import 'dart:ffi';

import 'package:blockben/secret/bls/id_vec.dart';
import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/signature_vec.dart';
import 'package:blockben/secret/bls/structs/bls_signature_ffi.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';
import 'package:ffi/ffi.dart';

class Signature {
  Signature() {
    _pointer = calloc<BlsSignature>();
  }

  late final Pointer<BlsSignature> _pointer;

  Pointer<BlsSignature> get pointer => _pointer;

  ByteArray serialize() {
    const maxSize = 48;
    final Pointer<Byte> bufPointer = calloc<Byte>(maxSize);

    try {
      final serializedSize = nativeFunctions.sig
          .blsSignatureSerialize(bufPointer.cast(), maxSize, _pointer);
      if (serializedSize != maxSize) {
        throw Exception('Serialization failed');
      }

      return ByteArray.fromList(bufPointer.asTypedList(serializedSize));
    } finally {
      calloc.free(bufPointer);
    }
  }

  void recover(SignatureVec signatureVec, IdVec idVec) {
    nativeFunctions.sig.blsSignatureRecover(
      pointer,
      signatureVec.pointer,
      idVec.pointer,
      signatureVec.length,
    );
  }

  bool verify(PublicKey publicKey, ByteArray sha512hash) {
    final hashSize = sha512hash.length;
    final hashPtr = calloc<Byte>(hashSize);

    final buf = hashPtr.asTypedList(hashSize);
    buf.setAll(0, sha512hash);
    for (int i = 0; i < hashSize; i++) {
      buf[i] = sha512hash[i];
    }

    final result = nativeFunctions.sig.blsVerify(
          pointer,
          publicKey.pointer,
          hashPtr.cast(),
          hashSize,
        ) ;

    calloc.free(hashPtr);

    return result == 1;
  }
}
