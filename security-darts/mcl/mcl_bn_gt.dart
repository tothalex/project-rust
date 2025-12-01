import 'dart:ffi';

import 'package:blockben/secret/mcl/mcl_bg_fp.dart';

final class MclBnGT extends Struct {
  @Array(mclBnGtUnitSize)
  external Array<MclBnFp> d;
}
const mclBnGtUnitSize = 12;
