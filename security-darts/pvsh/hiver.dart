import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/bls_id.dart';
import 'package:blockben/secret/bls/id_vec.dart';
import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/secret_key.dart';
import 'package:blockben/secret/bls/signature.dart';
import 'package:blockben/secret/bls/signature_vec.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/crypto/hasher.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';

abstract class Hiver {
  PublicKey toPublicKey(HexString data);

  SecretKey toSecretKey(HexString data);

  (HexString, HexString) generateKeyPairHex();

  BlsId generateId();

  Signature sign({required String data, required HexString secretKey});

  BlsId toId(HexString id);

  Signature recoverSign(List<Signature> sigVec, List<BlsId> idVec);

  bool verify(String data, PublicKey publicKey, Signature signature);
}

class HiverImpl implements Hiver {
  final Hasher _hasher;

  HiverImpl(this._hasher) {
    BLS.blsInit(BLS12_381);
  }

  @override
  PublicKey toPublicKey(HexString data) =>
      PublicKey()..deserialize(data.hexStrToByteArray());

  @override
  SecretKey toSecretKey(HexString data) =>
      SecretKey()..deserialize(data.hexStrToByteArray());

  @override
  (HexString, HexString) generateKeyPairHex() {
    final secretKey = SecretKey();
    secretKey.setByCSPRNG();
    return (
      secretKey.serialize().byteArrayToHexStr(),
      secretKey.publicKey.serialize().byteArrayToHexStr()
    );
  }

  /// blsIdByCSPRNG does not exist. We have to generate a
  /// Cryptographycally secure pseudo random number into id.v
  /// Because the SecretKey contains the same { MclBnFr v } ,
  /// we use the method of SecretKey, but renamed.
  @override
  BlsId generateId() {
    final id = BlsId();
    nativeFunctions.blsId.blsIdByCSPRNG(id.pointer);
    return id;
  }

  static const BLS12_381 = 5;

  @override
  Signature sign({required String data, required HexString secretKey}) {
    final sk = SecretKey()..deserialize(secretKey.hexStrToByteArray());
    final hash = _hasher.sha512Hash(data);
    return sk.sign(hash);
  }

  @override
  BlsId toId(HexString id) {
    return BlsId()..deserialize(id.hexStrToByteArray());
  }

  @override
  Signature recoverSign(List<Signature> sigVec, List<BlsId> idVec) {
    return Signature()..recover(SignatureVec(sigVec), IdVec(idVec));
  }

  @override
  bool verify(String data, PublicKey publicKey, Signature signature) {
    return signature.verify(publicKey, _hasher.sha512Hash(data));
  }
}

typedef HexString = String;
