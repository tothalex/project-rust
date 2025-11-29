use mcl_rust::*;
use crate::types::*;
use crate::crypto::{
    fr_evaluate_polynomial, fr_lagrange_interpolation,
    g2_evaluate_polynomial, g2_lagrange_interpolation,
    pvsh_encode_g2, pvsh_verify_g2, pvsh_decode_g2,
};

/// Convert bytes to a continuous hex string (no spaces, lowercase)
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hex_str = std::str::from_utf8(chunk)
                .map_err(|e| format!("Invalid UTF-8: {}", e))?;
            u8::from_str_radix(hex_str, 16)
                .map_err(|e| format!("Invalid hex: {}", e))
        })
        .collect()
}

/// Generate a contribution for threshold secret sharing
///
/// This implements the core of Shamir's threshold secret sharing scheme.
///
/// # Arguments
/// * `threshold` - Minimum number of shares needed to reconstruct the secret (k)
/// * `members` - List of members who will receive shares
///
/// # Returns
/// A `Contribution` containing:
/// - `pg`: Public generators (threshold number of public keys from the polynomial coefficients)
/// - `esh`: Encrypted shares for each member
///
/// # How it works
/// 1. Generate k random secret coefficients (for polynomial P(x) = a0 + a1*x + a2*x^2 + ...)
/// 2. Compute corresponding public keys (generators)
/// 3. For each member, evaluate polynomial at their ID to create their secret share
/// 4. Encrypt each share for the intended recipient (PVSH - Publicly Verifiable Secret Handoff)
pub fn generate_contribution(threshold: usize, members: &[Member]) -> Result<Contribution, String> {
    if threshold == 0 {
        return Err("Threshold must be at least 1".to_string());
    }
    if members.is_empty() {
        return Err("Members list cannot be empty".to_string());
    }
    if threshold > members.len() {
        return Err("Threshold cannot exceed number of members".to_string());
    }

    // Step 1: Generate random secret coefficients for the polynomial
    // P(x) = SG[0] + SG[1]*x + SG[2]*x^2 + ... + SG[threshold-1]*x^(threshold-1)
    let mut secret_coefficients: Vec<Fr> = Vec::new();
    let mut public_generators: Vec<G2> = Vec::new();

    for _ in 0..threshold {
        // Generate random secret coefficient
        let mut sg = Fr::zero();
        sg.set_by_csprng();

        // Compute corresponding public key (generator)
        let mut pg = unsafe { G2::uninit() };
        let g2_base = {
            let mut base = unsafe { G2::uninit() };
            base.set_hash_of(b"generator");
            base
        };
        G2::mul(&mut pg, &g2_base, &sg);

        secret_coefficients.push(sg);
        public_generators.push(pg);
    }

    // Create helper generator (same for all shares)
    let helper_g2 = {
        let mut generator = unsafe { G2::uninit() };
        generator.set_hash_of(b"generator");
        generator
    };

    // Step 2: For each member, generate their secret share
    let mut encrypted_shares: Vec<EncryptedShare> = Vec::new();

    for member in members {
        // Deserialize member's ID from hex (convert hex string to bytes, then deserialize)
        let id_bytes = hex_to_bytes(&member.id)?;
        let mut member_id = Fr::zero();
        if !member_id.deserialize(&id_bytes) {
            return Err(format!("Failed to deserialize member ID: {}", member.id));
        }

        // Deserialize member's public key from hex
        let pk_bytes = hex_to_bytes(&member.pm)?;
        let mut member_pk = unsafe { G2::uninit() };
        if !member_pk.deserialize(&pk_bytes) {
            return Err(format!("Failed to deserialize member public key: {}", member.pm));
        }

        // Evaluate polynomial at this member's ID to get their share
        // SH_k = P(member_id)
        let secret_share = fr_evaluate_polynomial(&secret_coefficients, &member_id)?;

        // Encrypt the share using PVSH (Publicly Verifiable Secret Handoff)
        let esh = pvsh_encode_g2(&member_id, &member_pk, &secret_share, &helper_g2)?;

        encrypted_shares.push(EncryptedShare {
            receiver_id: member.id.clone(),
            receiver_pk: member.pm.clone(),
            esh,
        });
    }

    // Step 3: Convert public generators to hex strings (serialize to bytes first)
    let pg_hex: Vec<String> = public_generators
        .iter()
        .map(|pg| bytes_to_hex(&pg.serialize()))
        .collect();

    Ok(Contribution {
        pg: pg_hex,
        esh: encrypted_shares,
    })
}

/// Calculate threshold keys from received contributions
///
/// This function recovers the shared secret keys from multiple contributions.
/// It uses Lagrange interpolation to reconstruct the polynomial at x=0.
///
/// # Arguments
/// * `contributions` - List of contributions from different parties
/// * `my_id` - My ID (hex-encoded Fr)
/// * `my_secret_key` - My secret key (hex-encoded Fr)
///
/// # Returns
/// A `ThresholdKey` containing the recovered keys and any errors
///
/// # How it works
/// 1. For each contribution, verify the encrypted shares (PVSH verify)
/// 2. Decode the shares meant for me (PVSH decode)
/// 3. Recover public keys for all participants using Lagrange interpolation
/// 4. Recover the master public generator
pub fn calculate_threshold_keys(
    contributions: &[ReceivedContribution],
    my_id: &str,
    my_secret_key: &str,
) -> ThresholdKey {
    let mut errors = Vec::new();

    if contributions.is_empty() {
        errors.push(ThresholdError {
            sender_id: None,
            receiver_id: my_id.to_string(),
            reason: "No contributions provided".to_string(),
        });
        return ThresholdKey {
            id: my_id.to_string(),
            sh: String::new(),
            ph: String::new(),
            phs: Vec::new(),
            pg: String::new(),
            errors,
        };
    }

    // Parse my ID and secret key
    let my_id_bytes = match hex_to_bytes(my_id) {
        Ok(bytes) => bytes,
        Err(e) => {
            errors.push(ThresholdError {
                sender_id: None,
                receiver_id: my_id.to_string(),
                reason: format!("Failed to parse my ID as hex: {}", e),
            });
            return ThresholdKey {
                id: my_id.to_string(),
                sh: String::new(),
                ph: String::new(),
                phs: Vec::new(),
                pg: String::new(),
                errors,
            };
        }
    };

    let mut my_id_fr = Fr::zero();
    if !my_id_fr.deserialize(&my_id_bytes) {
        errors.push(ThresholdError {
            sender_id: None,
            receiver_id: my_id.to_string(),
            reason: "Failed to deserialize my ID".to_string(),
        });
        return ThresholdKey {
            id: my_id.to_string(),
            sh: String::new(),
            ph: String::new(),
            phs: Vec::new(),
            pg: String::new(),
            errors,
        };
    }

    // Structure to hold all participants' shares
    #[derive(Clone)]
    struct ParticipantData {
        secret_shares: Vec<Fr>,       // My decoded secret shares (if I'm the receiver)
        public_shares: Vec<G2>,       // Public shares from each contribution
        sender_ids: Vec<Fr>,           // Sender IDs for recovery
    }

    let mut participants: std::collections::HashMap<String, ParticipantData> = std::collections::HashMap::new();

    // Create helper generator (same one used in encoding)
    let helper_g2 = {
        let mut generator = unsafe { G2::uninit() };
        generator.set_hash_of(b"generator");
        generator
    };

    // Parse my secret key
    let mut my_sk_fr = Fr::zero();
    if !my_sk_fr.set_str(my_secret_key, 16) {
        errors.push(ThresholdError {
            sender_id: None,
            receiver_id: my_id.to_string(),
            reason: "Failed to parse my secret key".to_string(),
        });
        return ThresholdKey {
            id: my_id.to_string(),
            sh: String::new(),
            ph: String::new(),
            phs: Vec::new(),
            pg: String::new(),
            errors,
        };
    }

    // Process each contribution
    for received_contrib in contributions {
        let contribution = &received_contrib.contribution;

        // Parse sender ID
        let mut sender_id = Fr::zero();
        if !sender_id.set_str(&received_contrib.sender_id, 16) {
            errors.push(ThresholdError {
                sender_id: Some(received_contrib.sender_id.clone()),
                receiver_id: my_id.to_string(),
                reason: "Failed to parse sender ID".to_string(),
            });
            continue;
        }

        // Parse public generators for this contribution
        let mut pg_vec: Vec<G2> = Vec::new();
        for pg_hex in &contribution.pg {
            let mut pg = unsafe { G2::uninit() };
            if !pg.set_str(pg_hex, 16) {
                errors.push(ThresholdError {
                    sender_id: Some(received_contrib.sender_id.clone()),
                    receiver_id: my_id.to_string(),
                    reason: "Failed to parse public generator".to_string(),
                });
                continue;
            }
            pg_vec.push(pg);
        }

        // Process each encrypted share
        for esh_data in &contribution.esh {
            let receiver_id_str = &esh_data.receiver_id;

            // Parse receiver ID
            let mut receiver_id = Fr::zero();
            if !receiver_id.set_str(receiver_id_str, 16) {
                errors.push(ThresholdError {
                    sender_id: Some(received_contrib.sender_id.clone()),
                    receiver_id: receiver_id_str.clone(),
                    reason: "Failed to parse receiver ID".to_string(),
                });
                continue;
            }

            // Calculate public share using polynomial evaluation
            let public_share = match g2_evaluate_polynomial(&pg_vec, &receiver_id) {
                Ok(ph) => ph,
                Err(e) => {
                    errors.push(ThresholdError {
                        sender_id: Some(received_contrib.sender_id.clone()),
                        receiver_id: receiver_id_str.clone(),
                        reason: format!("Failed to evaluate polynomial: {}", e),
                    });
                    continue;
                }
            };

            // Parse receiver's public key
            let mut receiver_pk = unsafe { G2::uninit() };
            if !receiver_pk.set_str(&esh_data.receiver_pk, 16) {
                errors.push(ThresholdError {
                    sender_id: Some(received_contrib.sender_id.clone()),
                    receiver_id: receiver_id_str.clone(),
                    reason: "Failed to parse receiver public key".to_string(),
                });
                continue;
            }

            // PVSH verification - verify the encrypted share
            if let Err(reason) = pvsh_verify_g2(&receiver_id, &receiver_pk, &public_share, &esh_data.esh, &helper_g2) {
                errors.push(ThresholdError {
                    sender_id: Some(received_contrib.sender_id.clone()),
                    receiver_id: receiver_id_str.clone(),
                    reason,
                });
                continue;
            }

            // Get or create participant data
            let participant = participants.entry(receiver_id_str.clone()).or_insert(ParticipantData {
                secret_shares: Vec::new(),
                public_shares: Vec::new(),
                sender_ids: Vec::new(),
            });

            participant.public_shares.push(public_share);
            participant.sender_ids.push(sender_id.clone());

            // If this share is for me, decode it using PVSH
            if receiver_id_str == my_id {
                match pvsh_decode_g2(&receiver_id, &receiver_pk, &my_sk_fr, &esh_data.esh) {
                    Ok(secret_share) => {
                        participant.secret_shares.push(secret_share);
                    }
                    Err(e) => {
                        errors.push(ThresholdError {
                            sender_id: Some(received_contrib.sender_id.clone()),
                            receiver_id: receiver_id_str.clone(),
                            reason: format!("Failed to decode secret share: {}", e),
                        });
                    }
                }
            }
        }
    }

    // Recover keys for all participants using Lagrange interpolation
    let mut phs = Vec::new();
    let mut my_recovered_secret = None;
    let mut my_recovered_public = None;

    for (receiver_id_str, participant) in participants {
        // Recover public key using Lagrange interpolation
        if !participant.public_shares.is_empty() && !participant.sender_ids.is_empty() {
            match g2_lagrange_interpolation(&participant.sender_ids, &participant.public_shares) {
                Ok(recovered_ph) => {
                    let ph_hex = bytes_to_hex(&recovered_ph.serialize());

                    if receiver_id_str == my_id {
                        my_recovered_public = Some(recovered_ph);
                    }

                    phs.push(PublicShare {
                        id: receiver_id_str.clone(),
                        ph: ph_hex,
                    });
                }
                Err(e) => {
                    errors.push(ThresholdError {
                        sender_id: None,
                        receiver_id: receiver_id_str.clone(),
                        reason: format!("Failed to recover public key: {}", e),
                    });
                }
            }
        }

        // Recover secret key for me (if I received shares)
        if receiver_id_str == my_id && !participant.secret_shares.is_empty() && !participant.sender_ids.is_empty() {
            match fr_lagrange_interpolation(&participant.sender_ids, &participant.secret_shares) {
                Ok(recovered_sh) => {
                    // Verify that recovered secret matches recovered public
                    // In full implementation, we'd check: recovered_sh * G == recovered_ph
                    my_recovered_secret = Some(recovered_sh);
                }
                Err(e) => {
                    errors.push(ThresholdError {
                        sender_id: None,
                        receiver_id: receiver_id_str.clone(),
                        reason: format!("Failed to recover secret key: {}", e),
                    });
                }
            }
        }
    }

    // Recover master public generator (PG) using all participants' public keys
    let pg_recovered = if !phs.is_empty() {
        let ids: Vec<Fr> = phs.iter().map(|ps| {
            let mut id = Fr::zero();
            id.set_str(&ps.id, 16);
            id
        }).collect();

        let phs_g2: Vec<G2> = phs.iter().map(|ps| {
            let mut ph = unsafe { G2::uninit() };
            ph.set_str(&ps.ph, 16);
            ph
        }).collect();

        match g2_lagrange_interpolation(&ids, &phs_g2) {
            Ok(pg) => bytes_to_hex(&pg.serialize()),
            Err(e) => {
                errors.push(ThresholdError {
                    sender_id: None,
                    receiver_id: my_id.to_string(),
                    reason: format!("Failed to recover master PG: {}", e),
                });
                String::new()
            }
        }
    } else {
        String::new()
    };

    ThresholdKey {
        id: my_id.to_string(),
        sh: my_recovered_secret.map(|s| bytes_to_hex(&s.serialize())).unwrap_or_default(),
        ph: my_recovered_public.map(|p| bytes_to_hex(&p.serialize())).unwrap_or_default(),
        phs,
        pg: pg_recovered,
        errors,
    }
}

/// Generate actor share from an actor contract
///
/// This is the main entry point for recovering threshold keys from an actor contract.
/// It calls `calculate_threshold_keys` and packages the result into an `ActorShareDataDevice`.
///
/// # Arguments
/// * `actor_id` - The actor ID
/// * `actor_contract` - The contract containing contributions and share metadata
/// * `my_id` - My ID (hex-encoded Fr)
/// * `my_secret_key` - My secret key (hex-encoded Fr)
///
/// # Returns
/// An `ActorShareDataDevice` containing all the recovered keys and share metadata
pub fn generate_actor_share(
    actor_id: &str,
    actor_contract: &ActorContract,
    my_id: &str,
    my_secret_key: &str,
) -> Result<ActorShareDataDevice, String> {
    // Calculate threshold keys from contributions
    let threshold_keys = calculate_threshold_keys(
        &actor_contract.contributions,
        my_id,
        my_secret_key,
    );

    // Check for errors
    if !threshold_keys.errors.is_empty() {
        let error_messages: Vec<String> = threshold_keys.errors
            .iter()
            .map(|e| format!("{} -> {}: {}",
                e.sender_id.as_ref().unwrap_or(&"<unknown>".to_string()),
                e.receiver_id,
                e.reason))
            .collect();
        return Err(format!("Errors found during calculating the shared key:\n{}",
            error_messages.join("\n")));
    }

    // Package into ActorShareDataDevice
    Ok(ActorShareDataDevice {
        actor_id: actor_id.to_string(),
        role_code: ActorRoleCode::DeviceReg, // Default for now
        share_code: actor_contract.actor_share.share_code.clone(),
        subject_actor_id: actor_contract.actor_share.subject_actor_id.clone(),
        hat_id: actor_contract.actor_share.hat_id.clone(),
        from_actor_id: actor_contract.actor_share.from_actor_id.clone(),
        to_actor_id: actor_contract.actor_share.to_actor_id.clone(),
        owner_actor_id: actor_contract.actor_share.owner_actor_id.clone(),
        pg: threshold_keys.pg,
        sh: threshold_keys.sh,
        ph: threshold_keys.ph,
        phs: threshold_keys.phs,
    })
}
