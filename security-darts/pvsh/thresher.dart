// ignore_for_file: non_constant_identifier_names

import 'package:blockben/model/actor_contract/actor_contract.dart';
import 'package:blockben/model/actor_contract/contribution.dart';
import 'package:blockben/model/actor_contract/esh.dart';
import 'package:blockben/model/actor_contract/member.dart';
import 'package:blockben/model/actor_contract/received_contribution.dart';
import 'package:blockben/model/id_with_public_key.dart';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/bls_id.dart';
import 'package:blockben/secret/bls/id_vec.dart';
import 'package:blockben/secret/bls/ph_item.dart';
import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/public_key_vec.dart';
import 'package:blockben/secret/bls/secret_key.dart';
import 'package:blockben/secret/bls/secret_key_calculation_error.dart';
import 'package:blockben/secret/bls/secret_key_vec.dart';
import 'package:blockben/secret/bls/threshold_key.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/mcl/fr.dart';
import 'package:blockben/secret/mcl/g1.dart';
import 'package:blockben/secret/mcl/g2.dart';
import 'package:blockben/secret/pvsh/hiver.dart';
import 'package:collection/collection.dart';

class Thresher {
  String PVSHEncodeG2({
    required BlsId ID,
    required SecretKey sh,
    required PublicKey pk,
    required G2 helperG2,
  }) {
    //Algorithm 1
    final r = Fr()..setByCSPRNG();

    //Algorithm 2
    final Q = BLS.hashAndMapToG1(ID.serialize().plus(pk.serialize()));

    //Algorithm 3
    final e = BLS.pairing(Q, BLS.mulG2(pk.toG2(), r));
    final eh = BLS.hashToFr(e.serialize());
    e.clear();

    //Algorithm 4
    final c = BLS.add(sh.toFr(), eh);

    //Algorithm 5
    final U = BLS.mulG2(helperG2, r);

    //Algorithm 6
    final H = BLS.hashAndMapToG1(
      Q.serialize().plus(c.serialize()).plus(U.serialize()),
    );

    //Algorithm 7
    final V = BLS.mulG1(H, BLS.div(eh, r));
    H.clear();
    eh.clear();
    r.clear();

    //Algorithm 8
    final resultStr =
        '${c.serialize().byteArrayToHexStr()}.${U.serialize().byteArrayToHexStr()}.${V.serialize().byteArrayToHexStr()}';
    Q.clear();
    c.clear();
    U.clear();
    V.clear();

    return resultStr;
  }

  String PVSHVerifyG2({
    required BlsId ID,
    required PublicKey PK,
    required PublicKey PH,
    required String ESH,
    required G2 helperG2,
  }) {
    //Deserialize necessary values from ESH
    final ESHArray = _getESHArray(ESH);

    final c = Fr()..deserialize(ESHArray[0].hexStrToByteArray());
    final U = G2()..deserialize(ESHArray[1].hexStrToByteArray());
    final V = G1()..deserialize(ESHArray[2].hexStrToByteArray());

    //Algorithm 1
    final Q = BLS.hashAndMapToG1(ID.serialize().plus(PK.serialize()));

    //Algorithm 2
    final H = BLS
        .hashAndMapToG1(Q.serialize().plus(c.serialize()).plus(U.serialize()));

    //Algorithm 3
    final e1 = BLS.pairing(H, BLS.mulG2(helperG2, c));
    final e2 = BLS.mulGT(BLS.pairing(H, PH.toG2()), BLS.pairing(V, U));

    //Algorithm 4
    if (!e1.equals(e2)) {
      return 'MISMATCH_PH_AND_CIPHER_TEXT';
    }

    return '';
  }

  SecretKey PVSHDecodeG2({
    required BlsId ID,
    required PublicKey PK,
    required SecretKey SK,
    required String ESH,
  }) {
    final ESHArray = _getESHArray(ESH);

    final c = Fr()..deserialize(ESHArray[0].hexStrToByteArray());
    final U = G2()..deserialize(ESHArray[1].hexStrToByteArray());

    //Algorithm 1
    final Q = BLS.hashAndMapToG1(ID.serialize().plus(PK.serialize()));

    //Algorithm 2
    final e = BLS.pairing(BLS.mulG1(Q, SK.toFr()), U);
    final eh = BLS.hashToFr(e.serialize());

    //Algorithm 3
    final sh = BLS.sub(c, eh);

    return SecretKey()..deserialize(sh.serialize());
  }

  Contribution<BlsId, PublicKey> calculateContribution({
    required int threshold,
    required List<Member<HexString, HexString>> members,
    HexString? oldSH,
  }) {
    final membersTemp = members.map(
      (member) => Member(
        id: BlsId()..deserialize(member.id.hexStrToByteArray()),
        pm: PublicKey()..deserialize(member.pm.hexStrToByteArray()),
      ),
    );
    SecretKey? oldSHTemp;
    if (oldSH != null) {
      oldSHTemp = SecretKey()..deserialize(oldSH.hexStrToByteArray());
    }
    return calculateContributionInternal(threshold, membersTemp, oldSHTemp);
  }

  Contribution<BlsId, PublicKey> calculateContributionInternal(
    int threshold,
    Iterable<Member<BlsId, PublicKey>> members,
    SecretKey? oldSH,
  ) {
    final helperG = BLS.getGeneratorOfPublicKey().toG2();
    final List<SecretKey> SG = [];
    final List<PublicKey> PG = [];
    final List<ESH<BlsId, PublicKey>> esh = [];

    if (oldSH != null) {
      SG.add(oldSH);
      PG.add(oldSH.publicKey);
    }

    final startIndex = oldSH != null ? 1 : 0;
    for (int i = startIndex; i < threshold; i++) {
      final SG_j = SecretKey()..setByCSPRNG();
      SG.add(SG_j);
      PG.add(SG_j.publicKey);
    }

    for (final member in members) {
      final id = member.id;
      final SH_k = SecretKey()..share(SecretKeyVec(SG), id);
      final ESH_k = PVSHEncodeG2(
        ID: id,
        pk: member.pm,
        sh: SH_k,
        helperG2: helperG,
      );
      esh.add(
        ESH(receiverId: member.id, receiverPK: member.pm, esh: ESH_k),
      );
    }
    for (final SG_j in SG) {
      SG_j.clear();
    }
    return Contribution(
      pg: PG,
      esh: esh,
    );
  }

  Future<Contribution<HexString, HexString>> contributionToHex(
    Contribution<BlsId, PublicKey> contribution,
  ) async {
    return Contribution<HexString, HexString>(
      pg: contribution.pg
          .map(
            (it) => it.serialize().byteArrayToHexStr(),
          )
          .toList(),
      esh: contribution.esh
          .map(
            (it) => ESH<HexString, HexString>(
              receiverId: it.receiverId.serialize().byteArrayToHexStr(),
              esh: it.esh,
              receiverPK: it.receiverPK.serialize().byteArrayToHexStr(),
            ),
          )
          .toList(),
    );
  }

  ThresholdKey<BlsId, SecretKey, PublicKey> calculateThresholdKeys({
    required List<ReceivedContribution<String, String>> receivedContributions,
    required String id,
    required String sm,
    required String actorShareId,
  }) {
    final receivedContributionTemp = receivedContributions.map((it) {
      final tmpId = BlsId()..deserialize(it.senderId.hexStrToByteArray());
      final contribution = _contributionFrom(it.contribution);
      return ReceivedContribution(
        senderId: tmpId,
        contribution: contribution,
      );
    });
    final meIDTemp = BlsId()..deserialize(id.hexStrToByteArray());
    final meSKTemp = SecretKey()..deserialize(sm.hexStrToByteArray());
    return _calculateSharedKeysInternal(
      receivedContributionTemp,
      meIDTemp,
      meSKTemp,
      actorShareId,
    );
  }

  Contribution<BlsId, PublicKey> _contributionFrom(
    Contribution<String, String> contribution,
  ) {
    return Contribution(
      pg: contribution.pg
          .map(
            (it) => PublicKey()..deserialize(it.hexStrToByteArray()),
          )
          .toList(),
      esh: contribution.esh
          .map(
            (it) => ESH(
              receiverId: BlsId()
                ..deserialize(it.receiverId.hexStrToByteArray()),
              esh: it.esh,
              receiverPK: PublicKey()
                ..deserialize(it.receiverPK.hexStrToByteArray()),
            ),
          )
          .toList(),
    );
  }

  ThresholdKey<BlsId, SecretKey, PublicKey> _calculateSharedKeysInternal(
    Iterable<ReceivedContribution<BlsId, PublicKey>> shares,
    BlsId meID,
    SecretKey meSK,
    String actorShareId,
  ) {
    final mePK = meSK.publicKey;
    final helperG = BLS.getGeneratorOfPublicKey().toG2();

    final List<SharedKeyCalculationError> errors = [];

    final List<PHItem> PHForAll = [];

    final PG = PublicKey()..clear();

    for (final shareItem in shares) {
      final senderId = shareItem.senderId;
      final PGi = shareItem.contribution.pg;
      final ESHi = shareItem.contribution.esh;
      for (final ESHik in ESHi) {
        //Algorithm 1
        final IDik = ESHik.receiverId;
        final PKik = ESHik.receiverPK;
        final PHik = PublicKey()..share(PublicKeyVec(PGi), IDik);

        //Algorithm 2
        final reason = PVSHVerifyG2(
          ID: IDik,
          PK: PKik,
          PH: PHik,
          ESH: ESHik.esh,
          helperG2: helperG,
        );
        if (reason.isNotEmpty) {
          errors.add(
            SharedKeyCalculationError(
              senderId: shareItem.senderId,
              receiverId: ESHik.receiverId,
              reason: reason,
            ),
          );
        }
        if (errors.isNotEmpty) {
          continue;
        }

        //Algorithm 6
        final phItem = PHForAll.firstWhere(
          (it) => it.ID.equals(ESHik.receiverId),
          orElse: () => PHItem(
            ID: ESHik.receiverId,
            SH: SecretKey(),
            SHk: [],
            PH: PublicKey(),
            PHk: [],
            SenderIds: [],
          ),
        );
        PHForAll.add(phItem);
        phItem.PHk.add(PHik);
        phItem.SenderIds.add(senderId);
        if (ESHik.receiverId.equals(meID)) {
          //Algorithm 3
          final SHik =
              PVSHDecodeG2(ID: IDik, PK: mePK, SK: meSK, ESH: ESHik.esh);
          phItem.SHk.add(SHik);
        }
      }
    }

    if (errors.isNotEmpty) {
      return ThresholdKey(
        id: BlsId(),
        sh: SecretKey(),
        ph: PublicKey(),
        phs: PHForAll.map(
          (it) => IdWithPublicKey(
            actorShareId: actorShareId,
            id: it.ID,
            ph: it.PH,
          ),
        ).toList(),
        pg: PublicKey(),
        errors: errors,
      );
    }

    for (final PHItem in PHForAll) {
      PHItem.PH.recover(
        PublicKeyVec(PHItem.PHk),
        IdVec(PHItem.SenderIds),
      );
      if (PHItem.SHk.isNotEmpty) {
        PHItem.SH.recover(
          SecretKeyVec(PHItem.SHk),
          IdVec(PHItem.SenderIds),
        );
        //Algorithm 5
        if (!PHItem.SH.publicKey.equals(PHItem.PH)) {
          errors.add(
            SharedKeyCalculationError(
              senderId: null,
              receiverId: PHItem.ID,
              reason: 'INVALID_SH_PH_FOR_ME',
            ),
          );
        }
      }
    }

    PG.recover(
      PublicKeyVec(PHForAll.map((it) => it.PH).toList()),
      IdVec(PHForAll.map((it) => it.ID).toList()),
    );
    final PHItem? mePH = PHForAll.firstWhereOrNull((it) => it.ID.equals(meID));
    return ThresholdKey(
      id: mePH?.ID ?? BlsId(),
      sh: mePH?.SH ?? SecretKey(),
      ph: mePH?.PH ?? PublicKey(),
      phs: PHForAll.map(
        (it) =>
            IdWithPublicKey(id: it.ID, ph: it.PH, actorShareId: actorShareId),
      ).toList(),
      pg: PG,
      errors: errors,
    );
  }

  ThresholdKey<HexString, HexString, HexString> thresholdKeyToHex({
    required ThresholdKey<BlsId, SecretKey, PublicKey> calculateThresholdKeys,
    required String actorShareId,
  }) {
    return ThresholdKey(
      id: calculateThresholdKeys.id.serialize().byteArrayToHexStr(),
      sh: calculateThresholdKeys.sh.serialize().byteArrayToHexStr(),
      ph: calculateThresholdKeys.ph.serialize().byteArrayToHexStr(),
      phs: calculateThresholdKeys.phs
          .map(
            (it) => IdWithPublicKey(
              actorShareId: actorShareId,
              id: it.id.serialize().byteArrayToHexStr(),
              ph: it.ph.serialize().byteArrayToHexStr(),
            ),
          )
          .toList(),
      pg: calculateThresholdKeys.pg.serialize().byteArrayToHexStr(),
      errors: calculateThresholdKeys.errors,
    );
  }

  Future<Contribution<HexString, HexString>> generateContribution(
    ActorContract actorContract,
  ) {
    return contributionToHex(
      calculateContribution(
        threshold: actorContract.threshold,
        members: actorContract.newMembers,
      ),
    );
  }
}

List<String> _getESHArray(String ESH) {
  final ESHArray = ESH.split('.');
  if (ESHArray.length != 3) {
    throw Exception('Invalid ESH');
  }
  return ESHArray;
}
