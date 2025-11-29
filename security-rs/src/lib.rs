// ============================================================================
// Security Library - BLS Threshold Secret Sharing
// ============================================================================
//
// This library implements threshold secret sharing using BLS12-381 elliptic curve
// cryptography with PVSH (Publicly Verifiable Secret Handoff) encryption.
//
// ## Modules
//
// - `types`: All type definitions (structs, enums)
// - `crypto`: Cryptographic primitives (BLS, secret sharing, PVSH)
// - `device`: Device storage operations
// - `threshold`: Threshold secret sharing operations
//
// ## Usage
//
// ```rust
// use security::*;
//
// // Initialize BLS library
// init_bls();
//
// // Generate device storage
// let storage = generate_device_storage("My Device");
//
// // Generate threshold contribution
// let members = vec![/* ... */];
// let contribution = generate_contribution(3, &members)?;
//
// // Generate actor share
// let actor_share = generate_actor_share(
//     "actor-id",
//     &actor_contract,
//     "my-id",
//     "my-secret-key",
// )?;
// ```

// Module declarations
pub mod crypto;
pub mod device;
mod http;
pub mod threshold;
pub mod types;

// Re-export commonly used types
pub use types::*;

// Re-export crypto functions
pub use crypto::{generate_id_hex, generate_keypair_hex, init_bls};

// Re-export device functions
pub use device::generate_device_storage;

// Re-export threshold functions
pub use threshold::{calculate_threshold_keys, generate_actor_share, generate_contribution};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::secret_sharing::{fr_evaluate_polynomial, fr_lagrange_interpolation};
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

        // IDs should be different
        assert_ne!(id1, id2);

        // IDs should be non-empty hex strings
        assert!(!id1.is_empty());
        assert!(!id2.is_empty());

        println!("ID 1: {}", id1);
        println!("ID 2: {}", id2);
    }

    #[test]
    fn test_keypair_generation() {
        initialize();

        let keypair1 = generate_keypair_hex();
        let keypair2 = generate_keypair_hex();

        // Keys should be different each time
        assert_ne!(keypair1.secret_key, keypair2.secret_key);
        assert_ne!(keypair1.public_key, keypair2.public_key);

        // Keys should be hex strings (non-empty)
        assert!(!keypair1.secret_key.is_empty());
        assert!(!keypair1.public_key.is_empty());

        println!("Keypair 1 Secret: {}", keypair1.secret_key);
        println!("Keypair 1 Public: {}", keypair1.public_key);
    }

    #[test]
    fn test_generate_device_storage() {
        initialize();

        // Generate device storage
        let storage = generate_device_storage("Test Device");

        // Verify structure
        assert_eq!(storage.name, "Test Device");
        assert!(!storage.id.is_empty());
        assert!(!storage.sm.is_empty());
        assert!(!storage.pm.is_empty());
        assert!(!storage.shared_device_data.id.is_empty());
        assert!(!storage.shared_device_data.sm.is_empty());
        assert!(!storage.shared_device_data.pm.is_empty());
        assert_eq!(storage.shared_device_data.actor_shares.len(), 0);

        println!("\n=== Device Storage Generated ===");
        println!("Device ID: {}", storage.id);
        println!("Device Secret Key: {}", storage.sm);
        println!("Device Public Key: {}", storage.pm);
        println!("Shared Data ID: {}", storage.shared_device_data.id);
        println!("Shared Secret Key: {}", storage.shared_device_data.sm);
        println!("Shared Public Key: {}", storage.shared_device_data.pm);
    }

    #[test]
    fn test_secret_sharing() {
        initialize();

        println!("\n=== Testing Secret Sharing (Shamir's Threshold) ===");

        // Create a secret (random Fr element)
        use mcl_rust::Fr;
        let mut secret = Fr::zero();
        secret.set_by_csprng();
        println!("Original Secret: {}", secret.get_str(16));

        // Create polynomial coefficients (threshold = 3)
        // P(x) = secret + a1*x + a2*x^2
        let threshold = 3;
        let mut coefficients = vec![secret.clone()];
        for _ in 1..threshold {
            let mut coeff = Fr::zero();
            coeff.set_by_csprng();
            coefficients.push(coeff);
        }

        // Generate shares for 5 parties (IDs: 1, 2, 3, 4, 5)
        let num_parties = 5;
        let mut ids = Vec::new();
        let mut shares = Vec::new();

        for i in 1..=num_parties {
            let mut id = Fr::zero();
            id.set_int(i);
            ids.push(id.clone());

            // Evaluate polynomial at this ID to get the share
            let share =
                fr_evaluate_polynomial(&coefficients, &id).expect("Failed to generate share");
            shares.push(share.clone());

            println!("Party {}: Share = {}", i, share.get_str(16));
        }

        // Now recover secret using any 3 shares (threshold)
        let ids_subset = vec![ids[0].clone(), ids[1].clone(), ids[2].clone()];
        let shares_subset = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];

        let recovered = fr_lagrange_interpolation(&ids_subset, &shares_subset)
            .expect("Failed to recover secret");

        println!("Recovered Secret: {}", recovered.get_str(16));
        println!("Original  Secret: {}", secret.get_str(16));

        // Verify recovery worked
        assert_eq!(
            secret.get_str(16),
            recovered.get_str(16),
            "Secret recovery failed!"
        );

        println!("✓ Secret sharing and recovery successful!");

        // Test with different subset (parties 2, 3, 4)
        let ids_subset2 = vec![ids[1].clone(), ids[2].clone(), ids[3].clone()];
        let shares_subset2 = vec![shares[1].clone(), shares[2].clone(), shares[3].clone()];

        let recovered2 = fr_lagrange_interpolation(&ids_subset2, &shares_subset2)
            .expect("Failed to recover secret with second subset");

        assert_eq!(
            secret.get_str(16),
            recovered2.get_str(16),
            "Secret recovery with different subset failed!"
        );

        println!("✓ Recovery with different subset also successful!");
    }

    #[test]
    fn test_generate_contribution() {
        initialize();

        println!("\n=== Testing generateContribution() ===");

        // Create test members
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

        // Generate contribution with threshold = 3
        let threshold = 3;
        let contribution =
            generate_contribution(threshold, &members).expect("Failed to generate contribution");

        println!("Threshold: {}", threshold);
        println!("Number of members: {}", members.len());
        println!("Number of public generators: {}", contribution.pg.len());
        println!("Number of encrypted shares: {}", contribution.esh.len());

        // Verify structure
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

        // Verify each member has a share
        for (i, member) in members.iter().enumerate() {
            let esh = &contribution.esh[i];
            assert_eq!(esh.receiver_id, member.id);
            assert_eq!(esh.receiver_pk, member.pm);
            assert!(!esh.esh.is_empty(), "Encrypted share should not be empty");
            println!(
                "Member {}: ID={}, ESH={}",
                i + 1,
                &esh.receiver_id[..16],
                &esh.esh[..32]
            );
        }

        println!("✓ Contribution generated successfully!");
        println!("\n✅ Using FULL PVSH encryption with pairing operations!");
    }

    #[test]
    fn test_generate_actor_share() {
        initialize();

        println!("\n=== Testing generateActorShare() - Full Threshold Workflow ===");

        // Simulate 3 parties participating in threshold secret sharing
        let threshold = 2; // Need 2 parties to reconstruct
        let num_parties = 3;

        // Create parties with IDs and keys
        let mut parties = Vec::new();
        for i in 0..num_parties {
            let id = generate_id_hex();
            let keypair = generate_keypair_hex();
            parties.push((id, keypair));
            println!("Party {}: ID={}", i + 1, &parties[i].0[..16]);
        }

        // Create members list (all parties)
        let members: Vec<Member> = parties
            .iter()
            .map(|(id, keypair)| Member {
                id: id.clone(),
                pm: keypair.public_key.clone(),
            })
            .collect();

        // Each party generates a contribution
        let mut all_contributions = Vec::new();
        for i in 0..num_parties {
            let contribution = generate_contribution(threshold, &members)
                .expect("Failed to generate contribution");

            println!(
                "\nParty {} contribution: {} public generators, {} shares",
                i + 1,
                contribution.pg.len(),
                contribution.esh.len()
            );

            all_contributions.push(ReceivedContribution {
                sender_id: parties[i].0.clone(),
                contribution,
            });
        }

        // Create an actor contract
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

        // Each party recovers their actor share
        println!("\n--- Recovering Actor Shares ---");
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
                    println!("\n Party {} recovered actor share:", i + 1);
                    println!("  Actor ID: {}", actor_share.actor_id);
                    println!("  Share Code: {}", actor_share.share_code);
                    println!("  PG (master): {}", &actor_share.pg[..32]);
                    println!("  SH (secret): {}", &actor_share.sh[..32]);
                    println!("  PH (public): {}", &actor_share.ph[..32]);
                    println!("  Number of public shares: {}", actor_share.phs.len());

                    // Verify structure
                    assert_eq!(actor_share.actor_id, actor_id);
                    assert_eq!(actor_share.share_code, "test-share-123");
                    assert!(!actor_share.pg.is_empty(), "PG should not be empty");
                    assert!(!actor_share.sh.is_empty(), "SH should not be empty");
                    assert!(!actor_share.ph.is_empty(), "PH should not be empty");
                    assert_eq!(
                        actor_share.phs.len(),
                        num_parties,
                        "Should have public shares for all parties"
                    );
                }
                Err(e) => {
                    panic!("Party {} failed to recover actor share: {}", i + 1, e);
                }
            }
        }

        println!("\n✓ All parties successfully recovered their actor shares!");
        println!("\n✅ PVSH verification and decryption are FULLY IMPLEMENTED!");
        println!(
            "All shares are cryptographically verified and decrypted using pairing operations."
        );
    }
}
