import 'dart:ffi';
import 'dart:io';

import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/fr.dart';
import 'package:blockben/secret/mcl/g1.dart';
import 'package:blockben/secret/mcl/g2.dart';
import 'package:blockben/secret/mcl/gt.dart';
import 'package:blockben/secret/native_bindings/native_functions.dart';

class BLS {
  factory BLS() {
    return _instance;
  }

  BLS._internal();
  static final BLS _instance = BLS._internal();

  static final DynamicLibrary nativeLib = Platform.isAndroid
      ? DynamicLibrary.open('libbls384_256.so')
      : DynamicLibrary.process();

  static int blsInit(int curve) {
    return nativeFunctions.bls.blsInit(curve, MCLBN_COMPILED_TIME_VAR);
  }

  static PublicKey getGeneratorOfPublicKey() {
    final publicKey = PublicKey();
    nativeFunctions.bls.blsGetGeneratorOfPublicKey(publicKey.pointer);
    return publicKey;
  }

  static G1 hashAndMapToG1(ByteArray s) {
    final x = G1();
    x.setHashOfWithByteArray(s);
    return x;
  }

  static GT pairing(G1 P, G2 Q) {
    final gt = GT();
    gt.pairing(P, Q);
    return gt;
  }

  static G1 mulG1(G1 x, Fr y) {
    final g1 = G1();
    g1.deserialize(x.serialize());
    g1.mul(y);
    return g1;
  }

  static G2 mulG2(G2 x, Fr y) {
    final g2 = G2();
    g2.deserialize(x.serialize());
    g2.mul(y);
    return g2;
  }

  static GT mulGT(GT x, GT y) {
    final gt = GT();
    gt.deserialize(x.serialize());
    gt.mul(y);
    return gt;
  }

  static Fr hashToFr(ByteArray s) {
    final fr = Fr();
    fr.setHashOfWithByteArray(s);
    return fr;
  }

  static Fr add(Fr x, Fr y) {
    final fr = Fr();
    fr.deserialize(x.serialize());
    fr.add(y);
    return fr;
  }

  static Fr div(Fr x, Fr y) {
    final fr = Fr();
    fr.deserialize(x.serialize());
    fr.div(y);
    return fr;
  }

  static Fr sub(Fr x, Fr y) {
    final fr = Fr();
    fr.deserialize(x.serialize());
    fr.sub(y);
    return fr;
  }

  static bool isDefinedBLS_ETH() {
    return false;
  }

  static const int MCLBN_FP_UNIT_SIZE = 6;
  static const int MCLBN_FR_UNIT_SIZE = 4;
  static const int MCLBN_COMPILED_TIME_VAR =
      MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE;
}
