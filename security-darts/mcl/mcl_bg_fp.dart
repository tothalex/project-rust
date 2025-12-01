import 'dart:ffi';

final class MclBnFp extends Struct {
  @Array(mclBnFpUnitSize)
  external Array<Uint64> d;
}

const mclBnFpUnitSize = 6;
