import 'dart:ffi';

import 'package:blockben/secret/mcl/mcl_bg_g1.dart';

final class BlsSignature extends Struct {
  external MclBnG1 v;
}
