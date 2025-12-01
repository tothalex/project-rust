import 'dart:ffi';

import 'package:blockben/secret/mcl/mcl_bn_fr.dart';

final class BlsSecretKey extends Struct {
  external MclBnFr v;
}
