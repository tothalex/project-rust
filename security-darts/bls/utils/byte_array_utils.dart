import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

extension HexConversion on String {
  ByteArray hexStrToByteArray() {
    final length = this.length;
    assert(length.isEven, 'Hex string must have an even length');

    final ByteArray bytes = ByteArray(length ~/ 2);
    for (int i = 0; i < length; i += 2) {
      bytes[i ~/ 2] = int.parse(substring(i, i + 2), radix: 16);
    }

    return bytes;
  }

  ByteArray base64ToByteArray() {
    return base64.decode(this);
  }
}

extension ByteConversion on ByteArray {
  String byteArrayToHexStr() {
    final StringBuffer sb = StringBuffer();

    for (final byte in this) {
      sb.write(byte.toRadixString(16).padLeft(2, '0'));
    }

    return sb.toString();
  }

  String byteArrayToBase64() {
    return base64.encode(this);
  }
}

extension ByteArrayPlus on ByteArray {
  ByteArray plus(ByteArray other) {
    final int thisSize = length;
    final int otherSize = other.length;

    final ByteArray result = ByteArray(thisSize + otherSize);
    result.setRange(0, thisSize, this);
    result.setRange(thisSize, thisSize + otherSize, other);

    return result;
  }
}

typedef ByteArray = Uint8List;
typedef Byte = Uint8;
