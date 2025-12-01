pub mod crypto;
pub mod device;
pub mod types;

pub use crypto::generate_id_hex;
pub use crypto::generate_keypair_hex;
pub use crypto::init_bls;
pub use crypto::threshold::{
    calculate_threshold_keys, generate_actor_share, generate_contribution,
};
pub use device::generate_device_storage;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ffi::*;
    use crypto::secret_sharing::{fr_evaluate_polynomial, fr_lagrange_interpolation};
    use crypto::{serialize_fr, sign};
    use hex;
    use std::mem;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn initialize() {
        INIT.call_once(|| {
            init_bls();
        });
    }

    #[test]
    fn test_id_generation() {
        initialize();

        let id1 = generate_id_hex();
        let id2 = generate_id_hex();

        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
        assert!(!id2.is_empty());
    }

    #[test]
    fn test_keypair_generation() {
        initialize();

        let keypair1 = generate_keypair_hex();
        let keypair2 = generate_keypair_hex();

        assert_ne!(keypair1.secret_key, keypair2.secret_key);
        assert_ne!(keypair1.public_key, keypair2.public_key);

        assert!(!keypair1.secret_key.is_empty());
        assert!(!keypair1.public_key.is_empty());
    }

    #[test]
    fn test_signature_generation() {
        initialize();

        let keypair = generate_keypair_hex();
        let test_data = b"Hello, World!";
        let signature = sign(test_data, &keypair.secret_key).expect("Failed to sign data");

        assert!(!signature.is_empty());
        assert_eq!(signature.len() % 2, 0, "Signature should be valid hex");
    }

    #[test]
    fn test_generate_device_storage() {
        initialize();

        let storage = generate_device_storage("Test Device");

        assert_eq!(storage.name, "Test Device");
        assert!(!storage.id.is_empty());
        assert!(!storage.sm.is_empty());
        assert!(!storage.pm.is_empty());
        assert!(!storage.shared_device_data.id.is_empty());
        assert!(!storage.shared_device_data.sm.is_empty());
        assert!(!storage.shared_device_data.pm.is_empty());
        assert_eq!(storage.shared_device_data.actor_shares.len(), 0);
    }

    #[test]
    fn test_secret_sharing() {
        initialize();

        unsafe {
            let mut secret: mclBnFr = mem::zeroed();
            mclBnFr_setByCSPRNG(&mut secret);
            let secret_hex = hex::encode(serialize_fr(&secret));

            let threshold = 3;
            let mut coefficients = vec![secret];
            for _ in 1..threshold {
                let mut coeff: mclBnFr = mem::zeroed();
                mclBnFr_setByCSPRNG(&mut coeff);
                coefficients.push(coeff);
            }

            let num_parties = 5;
            let mut ids = Vec::new();
            let mut shares = Vec::new();

            for i in 1..=num_parties {
                let mut id: mclBnFr = mem::zeroed();
                mclBnFr_setInt(&mut id, i);
                ids.push(id);

                let share =
                    fr_evaluate_polynomial(&coefficients, &id).expect("Failed to generate share");
                shares.push(share);
            }

            let ids_subset = vec![ids[0], ids[1], ids[2]];
            let shares_subset = vec![shares[0], shares[1], shares[2]];

            let recovered = fr_lagrange_interpolation(&ids_subset, &shares_subset)
                .expect("Failed to recover secret");

            let recovered_hex = hex::encode(serialize_fr(&recovered));

            assert_eq!(recovered_hex, secret_hex, "Secret recovery failed!");

            let ids_subset2 = vec![ids[1], ids[2], ids[3]];
            let shares_subset2 = vec![shares[1], shares[2], shares[3]];

            let recovered2 = fr_lagrange_interpolation(&ids_subset2, &shares_subset2)
                .expect("Failed to recover secret with second subset");

            let recovered2_hex = hex::encode(serialize_fr(&recovered2));
            assert_eq!(
                recovered2_hex, secret_hex,
                "Secret recovery with different subset failed!"
            );
        }
    }

    #[test]
    fn test_generator_consistency() {
        initialize();

        unsafe {
            let mut test_secret: mclBnFr = mem::zeroed();
            mclBnFr_setInt(&mut test_secret, 42);

            let pk1 = crypto::derive_public_key_g2(&test_secret);

            let helper_g2 = crypto::get_g2_generator();
            let mut pk2: mclBnG2 = mem::zeroed();
            mclBnG2_mul(&mut pk2, &helper_g2, &test_secret);

            let pk1_hex = hex::encode(crypto::serialize_g2(&pk1));
            let pk2_hex = hex::encode(crypto::serialize_g2(&pk2));

            assert_eq!(pk1_hex, pk2_hex, "Generators are inconsistent!");
        }
    }

    #[test]
    fn test_pvsh_roundtrip() {
        initialize();

        use crypto::pvsh::{pvsh_decode_g2, pvsh_encode_g2, pvsh_verify_g2};
        use crypto::{deserialize_fr, deserialize_g2, get_g2_generator};

        unsafe {
            let receiver_keypair = generate_keypair_hex();
            let receiver_id_hex = generate_id_hex();
            let receiver_id_bytes = hex::decode(&receiver_id_hex).unwrap();
            let receiver_id = deserialize_fr(&receiver_id_bytes).unwrap();
            let receiver_pk_bytes = hex::decode(&receiver_keypair.public_key).unwrap();
            let receiver_pk = deserialize_g2(&receiver_pk_bytes).unwrap();
            let receiver_sk_bytes = hex::decode(&receiver_keypair.secret_key).unwrap();
            let receiver_sk = deserialize_fr(&receiver_sk_bytes).unwrap();

            let mut original_secret: mclBnFr = mem::zeroed();
            mclBnFr_setByCSPRNG(&mut original_secret);
            let original_hex = hex::encode(serialize_fr(&original_secret));

            let helper_g2 = get_g2_generator();

            let esh = pvsh_encode_g2(&receiver_id, &receiver_pk, &original_secret, &helper_g2)
                .expect("PVSH encode failed");

            let original_pub = crypto::derive_public_key_g2(&original_secret);

            match pvsh_verify_g2(&receiver_id, &receiver_pk, &original_pub, &esh, &helper_g2) {
                Ok(()) => (),
                Err(e) => panic!("PVSH verification failed: {}", e),
            }

            let decoded_secret = pvsh_decode_g2(&receiver_id, &receiver_pk, &receiver_sk, &esh)
                .expect("PVSH decode failed");
            let decoded_hex = hex::encode(serialize_fr(&decoded_secret));

            assert_eq!(
                original_hex, decoded_hex,
                "Decoded secret doesn't match original!"
            );
        }
    }

    #[test]
    fn test_contribution_with_both_pg_methods() {
        initialize();

        let member1_kp = generate_keypair_hex();
        let member1_id = generate_id_hex();
        let member2_kp = generate_keypair_hex();
        let member2_id = generate_id_hex();

        let members = vec![
            Member {
                id: member1_id.clone(),
                pm: member1_kp.public_key.clone(),
            },
            Member {
                id: member2_id.clone(),
                pm: member2_kp.public_key.clone(),
            },
        ];

        let threshold = 2;
        let contribution =
            generate_contribution(threshold, &members).expect("Failed to generate contribution");

        use crypto::{deserialize_fr, deserialize_g2, get_g2_generator, pvsh_decode_g2};
        unsafe {
            let member_id_bytes = hex::decode(&member1_id).unwrap();
            let member_id_fr = deserialize_fr(&member_id_bytes).unwrap();
            let member_pk_bytes = hex::decode(&member1_kp.public_key).unwrap();
            let member_pk = deserialize_g2(&member_pk_bytes).unwrap();
            let member_sk_bytes = hex::decode(&member1_kp.secret_key).unwrap();
            let member_sk = deserialize_fr(&member_sk_bytes).unwrap();

            let esh = &contribution.esh[0].esh;

            let decoded_share = pvsh_decode_g2(&member_id_fr, &member_pk, &member_sk, esh)
                .expect("Failed to decode share");

            let pg_bytes_0 = hex::decode(&contribution.pg[0]).unwrap();
            let pg0 = deserialize_g2(&pg_bytes_0).unwrap();
            let pg_bytes_1 = hex::decode(&contribution.pg[1]).unwrap();
            let pg1 = deserialize_g2(&pg_bytes_1).unwrap();

            let mut pg1_times_id: mclBnG2 = mem::zeroed();
            mclBnG2_mul(&mut pg1_times_id, &pg1, &member_id_fr);
            let mut expected_ph: mclBnG2 = mem::zeroed();
            mclBnG2_add(&mut expected_ph, &pg0, &pg1_times_id);

            let helper_g2 = get_g2_generator();
            let mut actual_ph: mclBnG2 = mem::zeroed();
            mclBnG2_mul(&mut actual_ph, &helper_g2, &decoded_share);

            let expected_ph_hex = hex::encode(crypto::serialize_g2(&expected_ph));
            let actual_ph_hex = hex::encode(crypto::serialize_g2(&actual_ph));

            assert_eq!(
                expected_ph_hex, actual_ph_hex,
                "PH mismatch! PVSH verification will fail."
            );

            use crypto::pvsh::pvsh_verify_g2;
            match pvsh_verify_g2(&member_id_fr, &member_pk, &expected_ph, esh, &helper_g2) {
                Ok(()) => (),
                Err(e) => panic!("PVSH verification failed: {}", e),
            }
        }
    }

    #[test]
    fn test_generate_contribution() {
        initialize();

        let members = vec![
            Member {
                id: generate_id_hex(),
                pm: generate_keypair_hex().public_key,
            },
            Member {
                id: generate_id_hex(),
                pm: generate_keypair_hex().public_key,
            },
            Member {
                id: generate_id_hex(),
                pm: generate_keypair_hex().public_key,
            },
            Member {
                id: generate_id_hex(),
                pm: generate_keypair_hex().public_key,
            },
            Member {
                id: generate_id_hex(),
                pm: generate_keypair_hex().public_key,
            },
        ];

        let threshold = 3;
        let contribution =
            generate_contribution(threshold, &members).expect("Failed to generate contribution");

        assert_eq!(
            contribution.pg.len(),
            threshold,
            "Should have threshold number of public generators"
        );
        assert_eq!(
            contribution.esh.len(),
            members.len(),
            "Should have one encrypted share per member"
        );

        for (i, member) in members.iter().enumerate() {
            let esh = &contribution.esh[i];
            assert_eq!(esh.receiver_id, member.id);
            assert_eq!(esh.receiver_pk, member.pm);
            assert!(!esh.esh.is_empty(), "Encrypted share should not be empty");
        }
    }

    #[test]
    fn test_generate_actor_share() {
        initialize();

        let threshold = 2;
        let num_parties = 3;

        let mut parties = Vec::new();
        for _ in 0..num_parties {
            let id = generate_id_hex();
            let keypair = generate_keypair_hex();
            parties.push((id, keypair));
        }

        let members: Vec<Member> = parties
            .iter()
            .map(|(id, keypair)| Member {
                id: id.clone(),
                pm: keypair.public_key.clone(),
            })
            .collect();

        let mut all_contributions = Vec::new();
        for i in 0..num_parties {
            let contribution = generate_contribution(threshold, &members)
                .expect("Failed to generate contribution");

            all_contributions.push(ReceivedContribution {
                sender_id: parties[i].0.clone(),
                contribution,
            });
        }

        let actor_contract = ActorContract {
            threshold,
            new_members: members.clone(),
            contributions: all_contributions,
            actor_share: ActorShareData {
                share_code: "test-share-123".to_string(),
                subject_actor_id: "subject-actor-001".to_string(),
                hat_id: "hat-001".to_string(),
                from_actor_id: "from-actor-001".to_string(),
                to_actor_id: "to-actor-001".to_string(),
                owner_actor_id: "owner-actor-001".to_string(),
            },
        };

        for i in 0..num_parties {
            let actor_id = format!("actor-{}", i + 1);
            let (party_id, party_keypair) = &parties[i];

            match generate_actor_share(
                &actor_id,
                &actor_contract,
                party_id,
                &party_keypair.secret_key,
            ) {
                Ok(actor_share) => {
                    assert_eq!(actor_share.actor_id, actor_id);
                    assert_eq!(actor_share.share_code, "test-share-123");
                    assert!(!actor_share.pg.is_empty(), "PG should not be empty");
                    assert!(!actor_share.sh.is_empty(), "SH should not be empty");
                    assert!(!actor_share.ph.is_empty(), "PH should not be empty");
                    assert_eq!(
                        actor_share.phs.len(),
                        threshold,
                        "Should have public shares for threshold number of contributors"
                    );
                }
                Err(e) => {
                    panic!("Party {} failed to recover actor share: {}", i + 1, e);
                }
            }
        }
    }

    #[test]
    fn test_pvsh_with_fixed_values() {
        initialize();

        use crypto::{
            deserialize_fr, deserialize_g2, get_g2_generator, pvsh_decode_g2, pvsh_encode_g2,
            pvsh_verify_g2,
        };

        // Fixed values from Dart test
        let id_hex = "4a281f344ca08e3ead4089a3aec4ff1c6e9c2d09c55fcd75dbbdd76e1a2e5742";
        let secret_key_hex = "cef20755f3f0af479227059165fe81779be3a46b677ec5a8511b3786e5269d65";
        let public_key_hex = "9bac11ab883ac3b19b49be33aa0924ca01a4111e0ec59b50becea424677b0473438cb5ae31857531d0c87c156a70f10f89db3157d5598959a679a50e7f2291522569ec4f873e3e6117de843f81de723dc483688faa80fbf84514539d2e451418";

        // id1Keys - the receiver's keypair
        let receiver_secret_key_hex =
            "963d51afb6ab2493e1e5ee58562e43e1f8aef47f980b9ba22a197cef1abfaf1a";
        let receiver_public_key_hex = "a7fccf1965b9f01b52264e0df8a6806b956a2386d555ade094a41061864204365f9a5c812be2501aa9efa543a9a61605a97ca3fe02a40e17a8cc0b96be411adb42b696e5aedcd124a64068a3c00e0eabc7701a73c4c503bcde3114bfd37f980d";

        // Deserialize the values
        let id_bytes = hex::decode(id_hex).unwrap();
        let id = deserialize_fr(&id_bytes).expect("Failed to deserialize ID");

        let sk_bytes = hex::decode(secret_key_hex).unwrap();
        let sk = deserialize_fr(&sk_bytes).expect("Failed to deserialize secret key");

        let pk_bytes = hex::decode(public_key_hex).unwrap();
        let pk = deserialize_g2(&pk_bytes).expect("Failed to deserialize public key");

        let receiver_sk_bytes = hex::decode(receiver_secret_key_hex).unwrap();
        let receiver_sk =
            deserialize_fr(&receiver_sk_bytes).expect("Failed to deserialize receiver secret key");

        let receiver_pk_bytes = hex::decode(receiver_public_key_hex).unwrap();
        let receiver_pk =
            deserialize_g2(&receiver_pk_bytes).expect("Failed to deserialize receiver public key");

        // Get G2 generator
        let helper_g2 = get_g2_generator();

        // PVSH Encode
        let esh = pvsh_encode_g2(&id, &receiver_pk, &sk, &helper_g2).expect("PVSH encode failed");

        // PVSH Verify
        match pvsh_verify_g2(&id, &receiver_pk, &pk, &esh, &helper_g2) {
            Ok(()) => println!("PVSH verification passed"),
            Err(e) => panic!("PVSH verification failed: {}", e),
        }

        // PVSH Decode
        let decoded_sk =
            pvsh_decode_g2(&id, &receiver_pk, &receiver_sk, &esh).expect("PVSH decode failed");

        // Verify decoded secret matches original
        let decoded_hex = hex::encode(serialize_fr(&decoded_sk));
        assert_eq!(
            secret_key_hex, decoded_hex,
            "Decoded secret key doesn't match original!"
        );
    }

    #[test]
    fn test_key_derivation_from_fixed_values() {
        initialize();

        use crypto::{derive_public_key_g2, deserialize_fr, serialize_g2};

        // Test that we can derive the correct public key from the secret key
        let secret_key_hex = "cef20755f3f0af479227059165fe81779be3a46b677ec5a8511b3786e5269d65";
        let expected_public_key_hex = "9bac11ab883ac3b19b49be33aa0924ca01a4111e0ec59b50becea424677b0473438cb5ae31857531d0c87c156a70f10f89db3157d5598959a679a50e7f2291522569ec4f873e3e6117de843f81de723dc483688faa80fbf84514539d2e451418";

        let sk_bytes = hex::decode(secret_key_hex).unwrap();
        let sk = deserialize_fr(&sk_bytes).expect("Failed to deserialize secret key");

        let derived_pk = derive_public_key_g2(&sk);
        let derived_pk_hex = hex::encode(serialize_g2(&derived_pk));

        assert_eq!(
            expected_public_key_hex, derived_pk_hex,
            "Derived public key doesn't match expected value"
        );
    }

    #[test]
    fn test_id_deserialization() {
        initialize();

        use crypto::{deserialize_fr, serialize_fr};

        let id_hex = "4a281f344ca08e3ead4089a3aec4ff1c6e9c2d09c55fcd75dbbdd76e1a2e5742";

        let id_bytes = hex::decode(id_hex).unwrap();
        let id = deserialize_fr(&id_bytes).expect("Failed to deserialize ID");

        // Serialize back and verify it matches
        let serialized_hex = hex::encode(serialize_fr(&id));

        assert_eq!(
            id_hex, serialized_hex,
            "ID serialization/deserialization roundtrip failed"
        );
    }
}
