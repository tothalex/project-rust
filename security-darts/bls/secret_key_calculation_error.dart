import 'package:blockben/secret/bls/bls_id.dart';

class SharedKeyCalculationError {
  final BlsId? senderId;
  final BlsId? receiverId;
  final String reason;

  SharedKeyCalculationError({
    required this.senderId,
    required this.receiverId,
    required this.reason,
  });
}
