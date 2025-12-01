import 'dart:ffi';

import 'package:blockben/secret/mcl/mcl_bg_fp.dart';

final class MclBnFp2 extends Struct {
  @Array(2)
  external Array<MclBnFp> d;
}
