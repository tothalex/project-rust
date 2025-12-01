import 'package:blockben/model/actor_contract/contribution.dart';
import 'package:blockben/model/actor_contract/member.dart';
import 'package:blockben/model/actor_contract/received_contribution.dart';
import 'package:blockben/secret/bls/bls.dart';
import 'package:blockben/secret/bls/bls_id.dart';
import 'package:blockben/secret/bls/public_key.dart';
import 'package:blockben/secret/bls/secret_key.dart';
import 'package:blockben/secret/bls/signature.dart';
import 'package:blockben/secret/bls/threshold_key.dart';
import 'package:blockben/secret/bls/utils/byte_array_utils.dart';
import 'package:blockben/secret/pvsh/hiver.dart';
import 'package:blockben/secret/pvsh/thresher.dart';
import 'package:blockben/services/uuid_provider.dart';
import 'package:flutter/material.dart';

class BlsTest {
  BlsTest(this.thresher, this.hiver, this.uuidProvider);

  Thresher thresher;
  Hiver hiver;
  UuidProvider uuidProvider;

  void tryBlsMethods() {
    const idHex =
        '4a281f344ca08e3ead4089a3aec4ff1c6e9c2d09c55fcd75dbbdd76e1a2e5742';
    const secretKeyHex =
        'cef20755f3f0af479227059165fe81779be3a46b677ec5a8511b3786e5269d65';
    const publicKeyHex =
        '9bac11ab883ac3b19b49be33aa0924ca01a4111e0ec59b50becea424677b0473438cb5ae31857531d0c87c156a70f10f89db3157d5598959a679a50e7f2291522569ec4f873e3e6117de843f81de723dc483688faa80fbf84514539d2e451418';
    const id1Keys = (
      '963d51afb6ab2493e1e5ee58562e43e1f8aef47f980b9ba22a197cef1abfaf1a',
      'a7fccf1965b9f01b52264e0df8a6806b956a2386d555ade094a41061864204365f9a5c812be2501aa9efa543a9a61605a97ca3fe02a40e17a8cc0b96be411adb42b696e5aedcd124a64068a3c00e0eabc7701a73c4c503bcde3114bfd37f980d'
    );

    debugPrint('id1 hex: $idHex');
    debugPrint('sk1 hex: $secretKeyHex');

    // Create BlsId, BlsSecretKey, and PublicKey from hex strings
    final id1 = BlsId()..deserialize(idHex.hexStrToByteArray());
    final sk1 = SecretKey()..deserialize(secretKeyHex.hexStrToByteArray());
    final pk1 = PublicKey()..deserialize(publicKeyHex.hexStrToByteArray());

    debugPrint('PVSH param - id1: ${id1.serialize().byteArrayToHexStr()}');
    debugPrint('PVSH param - sk1: ${sk1.serialize().byteArrayToHexStr()}');
    debugPrint('PVSH param - id1Keys.publicKey: ${id1Keys.$2}');
    debugPrint('PVSH param - id1Keys.secretKey: ${id1Keys.$1}');

    final pkGenerator = BLS.getGeneratorOfPublicKey();
    final helperG2 = pkGenerator.toG2();
    final esh1 = thresher.PVSHEncodeG2(
      ID: id1,
      sh: sk1,
      pk: hiver.toPublicKey(id1Keys.$2),
      helperG2: helperG2,
    );

    debugPrint('PVSH encode: $esh1');

    final verify = thresher.PVSHVerifyG2(
      ID: id1,
      PK: hiver.toPublicKey(id1Keys.$2),
      PH: pk1,
      ESH: esh1,
      helperG2: helperG2,
    );

    final error = verify.isEmpty ? 'No error' : verify;
    debugPrint('PVSH esh1: $esh1');
    debugPrint('PVSH verify: $error');

    final decoded = thresher.PVSHDecodeG2(
      ID: id1,
      PK: hiver.toPublicKey(id1Keys.$2),
      SK: hiver.toSecretKey(id1Keys.$1),
      ESH: esh1,
    );
    debugPrint('PVSH decode: ${decoded.serialize().byteArrayToHexStr()}');

    // Free allocated memory
    id1.dispose();
    sk1.clear();
    pk1.clear();
  }

  Future<void> runBlsExample() async {
    //textActorExample()
    //speedCheck_NPVDKG(1,1,false,3,2)

    debugPrint('EXAMPLE');

    /*const key1 = (
      '25d2af520fadfda40c8add4916ca094bf57e0dc4dac1fb6bccdf677739fde43f',
      'fad7810e0e4eef8e2b28df8ccaafec106a26edda9cf54aea66396851e58cde55b5ae3d26933111c4aca6c9ab8552bb0cad560e297ef957d0fc5b367eda7af8e7083796b353e7491c7a8c18137de131dbbdb4d2dcac8672f92419c9ab5fb07803'
    );
    const key2 = (
      'e8ca774dfc3371d3a91e221af7ec639beb8704c7806f9b42f1f903766aa84235',
      '3eb4427e963b4a8f485b6df67038b944cfec9016627786e3d2e27c072fbc4091345800aede6f90d8ee2c9496392a0e003e7bcf6e5799fbcde6368a5af1836b03a077b4d2ab7c4189abd8428daf76b91f3645704ec43f05c7f6694e4cbd2b9a90'
    );
    const key3 = (
      '5c078a83d3977498e8f66a9c99e4ae01147b18714e9e5be7e789e2c5f7fd8855',
      'cd145cf7cc1c3f96d254fe839d231a35ea2c5754eb3d515ddcbac9be4ce19ada843781479cda67d208aa650313e0ff0cb621f8d121f91d404e2dbe0e4ef93d48557d3cf28f603c21fc6cbc46115d3c83041dc3c4027ad26dcdb4d1d7b171438d'
    );
    const key4 = (
      'f8ff1437837d4516cbd2d0484f25985bea4c4d5659a11988deb174ad09966c6e',
      'de85a8ac8867fe4f93b72854ba33fe2a56dac2c1ca6fada28c38a282aed52e45a8f42aab6ad8ab807e560ee4b11c28131f3d2546f755c8fda7891161327cad75bca6bd2fa86464b7246a40d0624139596fa87f6410cf222a494c7570e2d33589'
    );*/
    final key1 = hiver.generateKeyPairHex();
    final key2 = hiver.generateKeyPairHex();
    final key3 = hiver.generateKeyPairHex();
    final key4 = hiver.generateKeyPairHex();

    /*const id1 =
        'd430aac9a3225fd8dcb1571f0bad3d37d2579863dd635150b7c1dfbd82b51637';
    const id2 =
        '5f7e65084ccfc1510ecc414064f49c6ae579b8b050b0d5977c7b943a924d6b6f';
    const id3 =
        'ac5bda75debd4daf4fdd809e7c97944344ef0a30d6b50f5108a5deec6387ea30';
    const id4 =
        '90fc49f7a204f479c69dac3246b566e8a58c708c917a986544fdb93fe68a742d';*/
    final id1 = hiver.generateId().serialize().byteArrayToHexStr();
    final id2 = hiver.generateId().serialize().byteArrayToHexStr();
    final id3 = hiver.generateId().serialize().byteArrayToHexStr();
    final id4 = hiver.generateId().serialize().byteArrayToHexStr();

    final member1 = IExampleMemberData(
      id: id1,
      sm: key1.$1,
      pm: key1.$2,
      receivedContributions: [],
    );
    final member2 = IExampleMemberData(
      id: id2,
      sm: key2.$1,
      pm: key2.$2,
      receivedContributions: [],
    );
    final member3 = IExampleMemberData(
      id: id3,
      sm: key3.$1,
      pm: key3.$2,
      receivedContributions: [],
    );
    final member4 = IExampleMemberData(
      id: id4,
      sm: key4.$1,
      pm: key4.$2,
      receivedContributions: [],
    );

    final participants = [
      Member(
        id: member1.id,
        pm: member1.pm,
      ),
      Member(
        id: member2.id,
        pm: member2.pm,
      ),
      Member(
        id: member3.id,
        pm: member3.pm,
      ),
      Member(
        id: member4.id,
        pm: member4.pm,
      ),
    ];

    //Member1 generates its own contribution (4/3)
    debugPrint('Member1 creating contributions');
    member1.contribution = await thresher.contributionToHex(
      thresher.calculateContribution(
        threshold: 3,
        members: participants,
      ),
    ) as Contribution<HexString, HexString>?;
    member1.receivedContributions.add(
      ReceivedContribution(
        senderId: member1.id,
        contribution: member1.contribution!,
      ),
    );
    //Member2 generates its own contribution (4/3)
    debugPrint('Member2 creating contributions');
    member2.contribution = await thresher.contributionToHex(
      thresher.calculateContribution(
        threshold: 3,
        members: participants,
      ),
    ) as Contribution<HexString, HexString>?;
    member2.receivedContributions.add(
      ReceivedContribution(
        senderId: member2.id,
        contribution: member2.contribution!,
      ),
    );
    //Member3 generates its own contribution (4/3)
    debugPrint('Member3 creating contributions');
    member3.contribution = await thresher.contributionToHex(
      thresher.calculateContribution(
        threshold: 3,
        members: participants,
      ),
    ) as Contribution<HexString, HexString>?;
    member3.receivedContributions.add(
      ReceivedContribution(
        senderId: member3.id,
        contribution: member3.contribution!,
      ),
    );
    //Member4 generates its own contribution (4/3)
    debugPrint('Member4 creating contributions');
    member4.contribution = await thresher.contributionToHex(
      thresher.calculateContribution(
        threshold: 3,
        members: participants,
      ),
    ) as Contribution<HexString, HexString>?;
    member4.receivedContributions.add(
      ReceivedContribution(
        senderId: member4.id,
        contribution: member4.contribution!,
      ),
    );

    //member1 receives more contribution and calculate shared key from the contributions
    debugPrint(
      'Member1 receiving contributions and calculate shared key from them',
    );
    member1.receivedContributions.addAll(
      [
        ReceivedContribution(
          senderId: member2.id,
          contribution: member2.contribution!,
        ),
        ReceivedContribution(
          senderId: member3.id,
          contribution: member3.contribution!,
        ),
        ReceivedContribution(
          senderId: member4.id,
          contribution: member4.contribution!,
        ),
      ],
    );
    var actorShareId = uuidProvider.get();
    member1.calculatedShare = thresher.thresholdKeyToHex(
      calculateThresholdKeys: thresher.calculateThresholdKeys(
        receivedContributions: member1.receivedContributions,
        id: member1.id,
        sm: member1.sm,
        actorShareId: actorShareId,
      ),
      actorShareId: actorShareId,
    );
    //member2 receives more contribution and calculate shared key from the contributions
    debugPrint(
      'Member2 receiving contributions and calculate shared key from them',
    );
    member2.receivedContributions.addAll([
      ReceivedContribution(
        senderId: member1.id,
        contribution: member1.contribution!,
      ),
      ReceivedContribution(
        senderId: member3.id,
        contribution: member3.contribution!,
      ),
      ReceivedContribution(
        senderId: member4.id,
        contribution: member4.contribution!,
      ),
    ]);
    actorShareId = uuidProvider.get();
    member2.calculatedShare = thresher.thresholdKeyToHex(
      calculateThresholdKeys: thresher.calculateThresholdKeys(
        receivedContributions: member2.receivedContributions,
        id: member2.id,
        sm: member2.sm,
        actorShareId: actorShareId,
      ),
      actorShareId: actorShareId,
    );
    //member3 receives more contribution and calculate shared key from the contributions
    debugPrint(
      'Member3 receiving contributions and calculate shared key from them',
    );
    member3.receivedContributions.addAll([
      ReceivedContribution(
        senderId: member1.id,
        contribution: member1.contribution!,
      ),
      ReceivedContribution(
        senderId: member2.id,
        contribution: member2.contribution!,
      ),
      ReceivedContribution(
        senderId: member4.id,
        contribution: member4.contribution!,
      ),
    ]);

    actorShareId = uuidProvider.get();
    member3.calculatedShare = thresher.thresholdKeyToHex(
      calculateThresholdKeys: thresher.calculateThresholdKeys(
        receivedContributions: member3.receivedContributions,
        id: member3.id,
        sm: member3.sm,
        actorShareId: actorShareId,
      ),
      actorShareId: actorShareId,
    );

    //member4 receives more contribution and calculate shared key from the contributions
    debugPrint(
      'Member4 receiving contributions and calculate shared key from them',
    );

    member4.receivedContributions.addAll(
      [
        ReceivedContribution(
          senderId: member1.id,
          contribution: member1.contribution!,
        ),
        ReceivedContribution(
          senderId: member2.id,
          contribution: member2.contribution!,
        ),
        ReceivedContribution(
          senderId: member3.id,
          contribution: member3.contribution!,
        ),
      ],
    );
    actorShareId = uuidProvider.get();
    member4.calculatedShare = thresher.thresholdKeyToHex(
      calculateThresholdKeys: thresher.calculateThresholdKeys(
        receivedContributions: member4.receivedContributions,
        id: member4.id,
        sm: member4.sm,
        actorShareId: actorShareId,
      ),
      actorShareId: actorShareId,
    );

    //Signature test
    debugPrint('Members creating signatures...');
    final List<MemberSign> memberSigns = [];

    //3 member create the signatures
    memberSigns.addAll([
      /*MemberSign(
                    id = hiver.toId(member1.id),
                    sig = hiver.sign("Kecske",  member1.calculatedShare?.sh)
                ),*/
      MemberSign(
        id: hiver.toId(member2.id),
        sig: hiver.sign(
          data: 'Kecske', // DON'T blame me, it is just a copy from legacy code
          secretKey: member2.calculatedShare!.sh,
        ),
      ),
      MemberSign(
        id: hiver.toId(member3.id),
        sig: hiver.sign(
          data: 'Kecske',
          secretKey: member3.calculatedShare!.sh,
        ),
      ),
      MemberSign(
        id: hiver.toId(member4.id),
        sig: hiver.sign(
          data: 'Kecske',
          secretKey: member4.calculatedShare!.sh,
        ),
      ),
    ]);

    //Any 3 of the signs can recover the final signature
    debugPrint('Creating final signatures...');
    final finalSig = hiver.recoverSign(
      memberSigns.map((it) => it.sig).toList(),
      memberSigns.map((it) => it.id).toList(),
    );
    debugPrint('Creating final signatures... DONE');

    debugPrint(
        'Member1 verification result of recovered signature: ${hiver.verify(
      "Kecske",
      hiver.toPublicKey(member1.calculatedShare!.pg),
      finalSig,
    )}');
    debugPrint(
        'Member2 verification result of recovered signature: ${hiver.verify(
      "Kecske",
      hiver.toPublicKey(member2.calculatedShare!.pg),
      finalSig,
    )}');
    debugPrint(
        "Member3 verification result of recovered signature: ${hiver.verify(
      "Kecske",
      hiver.toPublicKey(member3.calculatedShare!.pg),
      finalSig,
    )}");
    debugPrint(
        "Member4 verification result of recovered signature: ${hiver.verify(
      "Kecske",
      hiver.toPublicKey(member4.calculatedShare!.pg),
      finalSig,
    )}");
  }
}

class IExampleMemberData {
  final HexString id;
  final HexString sm;
  final HexString pm;
  Contribution<HexString, HexString>? contribution;
  final List<ReceivedContribution<HexString, HexString>> receivedContributions;
  ThresholdKey<HexString, HexString, HexString>? calculatedShare;

  IExampleMemberData({
    required this.id,
    required this.sm,
    required this.pm,
    required this.receivedContributions,
    this.contribution,
    this.calculatedShare,
  });
}

class MemberSign {
  final BlsId id;
  final Signature sig;

  MemberSign({required this.id, required this.sig});
}
