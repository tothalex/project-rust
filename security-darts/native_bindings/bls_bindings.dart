import 'dart:ffi';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/structs/bls_public_key.dart';

class BlsBindings {
  DynamicLibrary get _lib => BLS.nativeLib;

  // Native function binding for blsInit
  late final int Function(int curve, int compiledTimeVar) blsInit =
      _lookupBlsInit();

  // Native function binding for blsGetGeneratorOfPublicKey
  late final void Function(Pointer<BlsPublicKey> pub)
      blsGetGeneratorOfPublicKey = _lookupBlsGetGeneratorOfPublicKey();

  // Private method to lookup the blsInit function
  int Function(int curve, int compiledTimeVar) _lookupBlsInit() {
    return _lib.lookupFunction<
        Int32 Function(Int32 curve, Int32 compiledTimeVar),
        int Function(int curve, int compiledTimeVar)>('blsInit');
  }

  // Private method to lookup the blsGetGeneratorOfPublicKey function
  void Function(Pointer<BlsPublicKey> pub) _lookupBlsGetGeneratorOfPublicKey() {
    return _lib.lookupFunction<Void Function(Pointer<BlsPublicKey> pub),
        void Function(Pointer<BlsPublicKey> pub)>('blsGetGeneratorOfPublicKey');
  }
}
