import 'package:blockben/secret/bls/bls_id.dart';
import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/secret_key.dart';

class PHItem {
  BlsId ID;
  SecretKey SH;
  List<SecretKey> SHk;
  PublicKey PH;
  List<PublicKey> PHk;
  List<BlsId> SenderIds;

  PHItem({
    required this.ID,
    required this.SH,
    required this.SHk,
    required this.PH,
    required this.PHk,
    required this.SenderIds,
  });
}
