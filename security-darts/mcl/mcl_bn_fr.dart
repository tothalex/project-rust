import 'dart:ffi';

final class MclBnFr extends Struct {
  @Array(mclBnFrUnitSize)
  external Array<Uint64> d;
}

const int mclBnFrUnitSize = 4;
