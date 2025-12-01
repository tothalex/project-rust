import 'package:blockben/secret/native_bindings/bls_bindings.dart';
import 'package:blockben/secret/native_bindings/bls_id_bindings.dart';
import 'package:blockben/secret/native_bindings/fr_bindings.dart';
import 'package:blockben/secret/native_bindings/g1_bindings.dart';
import 'package:blockben/secret/native_bindings/g2_bindings.dart';
import 'package:blockben/secret/native_bindings/gt_bindings.dart';
import 'package:blockben/secret/native_bindings/public_key_bindings.dart';
import 'package:blockben/secret/native_bindings/secret_key_bindings.dart';
import 'package:blockben/secret/native_bindings/signature_bindings.dart';

class NativeFunctions {
  static final NativeFunctions _instance = NativeFunctions._internal();

  factory NativeFunctions() {
    return _instance;
  }

  NativeFunctions._internal();

  // Lazy initialization for GT, G1, G2 bindings
  late final _gtBindings = GTBindings();
  late final _g1Bindings = G1Bindings();
  late final _g2Bindings = G2Bindings();
  late final _frBindings = FrBindings();
  late final _skBindings = SecretKeyBindings();
  late final _pkBindings = PublicKeyBindings();
  late final _signatureBindings = SignatureBindings();
  late final _blsIdBindings = BlsIdBindings();
  late final _blsBindings = BlsBindings();

  // Expose the class-specific bindings via getters
  GTBindings get gt => _gtBindings;
  G1Bindings get g1 => _g1Bindings;
  G2Bindings get g2 => _g2Bindings;
  FrBindings get fr => _frBindings;
  SecretKeyBindings get sk => _skBindings;
  PublicKeyBindings get pk => _pkBindings;
  SignatureBindings get sig => _signatureBindings;
  BlsIdBindings get blsId => _blsIdBindings;
  BlsBindings get bls => _blsBindings;
}

// Global access for convenience
final NativeFunctions nativeFunctions = NativeFunctions();
