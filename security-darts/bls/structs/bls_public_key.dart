import 'dart:ffi';

import 'package:blockben/secret/mcl/mcl_bn_g2.dart';

final class BlsPublicKey extends Struct {
  external MclBnG2 v;
}
