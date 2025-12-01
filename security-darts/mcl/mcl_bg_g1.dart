import 'dart:ffi';
import 'package:blockben/secret/mcl/mcl_bg_fp.dart';

final class MclBnG1 extends Struct {
  external MclBnFp x;
  external MclBnFp y;
  external MclBnFp z;
}
