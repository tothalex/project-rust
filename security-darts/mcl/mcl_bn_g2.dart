import 'dart:ffi';
import 'package:blockben/secret/mcl/mcl_bn_fp2.dart';

final class MclBnG2 extends Struct {
  external MclBnFp2 x;
  external MclBnFp2 y;
  external MclBnFp2 z;
}
