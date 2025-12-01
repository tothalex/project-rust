import 'package:blockben/model/id_with_public_key.dart';
import 'package:blockben/secret/bls/secret_key_calculation_error.dart';

class ThresholdKey<TId, TSecretKey, TPublicKey> {
  final TId id;
  final TSecretKey sh;
  final TPublicKey ph;
  final List<IdWithPublicKey<TId, TPublicKey>> phs;
  final TPublicKey pg;
  final List<SharedKeyCalculationError> errors;

  ThresholdKey({
    required this.id,
    required this.sh,
    required this.ph,
    required this.phs,
    required this.pg,
    required this.errors,
  });
}
