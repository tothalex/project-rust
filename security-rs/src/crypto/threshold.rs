use super::ffi::*;
use crate::types::*;
use super::{
    pvsh_encode_g2, pvsh_decode_g2,
    serialize_fr, serialize_g2, deserialize_fr, deserialize_g2,
    derive_public_key_g2, get_g2_generator,
};
use super::utils::{bytes_to_hex, hex_to_bytes};
use std::mem;

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

    unsafe {
        let helper_g2 = get_g2_generator();

        let mut bls_secret_coefficients: Vec<BlsSecretKey> = Vec::new();
        let mut public_generators: Vec<mclBnG2> = Vec::new();

        for _ in 0..threshold {
            let mut bls_sg: BlsSecretKey = mem::zeroed();
            let ret = blsSecretKeySetByCSPRNG(&mut bls_sg);
            if ret != 0 {
                return Err("Failed to generate random secret key".to_string());
            }

            let mut bls_pg: BlsPublicKey = mem::zeroed();
            blsGetPublicKey(&mut bls_pg, &bls_sg);
            let pg = bls_pg.v;

            bls_secret_coefficients.push(bls_sg);
            public_generators.push(pg);
        }

        let mut encrypted_shares: Vec<EncryptedShare> = Vec::new();

        for member in members {
            let id_bytes = hex_to_bytes(&member.id)?;
            let member_id = deserialize_fr(&id_bytes)?;

            let pk_bytes = hex_to_bytes(&member.pm)?;
            let member_pk = deserialize_g2(&pk_bytes)?;

            let mut bls_id: BlsId = mem::zeroed();
            let id_bytes = serialize_fr(&member_id);
            let consumed =
                blsIdDeserialize(&mut bls_id, id_bytes.as_ptr() as *const _, id_bytes.len());
            if consumed == 0 {
                return Err("Failed to convert Fr to BlsId".to_string());
            }

            let mut member_share_bls: BlsSecretKey = mem::zeroed();
            let ret = blsSecretKeyShare(
                &mut member_share_bls,
                bls_secret_coefficients.as_ptr(),
                threshold,
                &bls_id,
            );
            if ret != 0 {
                return Err("blsSecretKeyShare failed".to_string());
            }

            let mut share_bytes = vec![0u8; BLS_SECRET_KEY_SIZE];
            let size = blsSecretKeySerialize(
                share_bytes.as_mut_ptr() as *mut _,
                BLS_SECRET_KEY_SIZE,
                &member_share_bls,
            );
            if size == 0 {
                return Err("Failed to serialize secret share".to_string());
            }
            let member_share = deserialize_fr(&share_bytes[..size])?;

            let esh = pvsh_encode_g2(&member_id, &member_pk, &member_share, &helper_g2)?;

            encrypted_shares.push(EncryptedShare {
                receiver_id: member.id.clone(),
                receiver_pk: member.pm.clone(),
                esh,
            });
        }

        let pg_hex: Vec<String> = public_generators
            .iter()
            .map(|pg| bytes_to_hex(&serialize_g2(pg)))
            .collect();

        Ok(Contribution {
            pg: pg_hex,
            esh: encrypted_shares,
        })
    }
}

pub fn calculate_threshold_keys(
    actor_id: &str,
    threshold: usize,
    _members: &[Member],
    contributions: &[ReceivedContribution],
) -> Result<ThresholdKeys, String> {
    if contributions.is_empty() {
        return Err("No contributions provided".to_string());
    }
    if contributions.len() < threshold {
        return Err(format!(
            "Not enough contributions: got {}, need {}",
            contributions.len(),
            threshold
        ));
    }

    let contributions_to_use = &contributions[..threshold];

    unsafe {
        let mut bls_contributor_ids: Vec<BlsId> = Vec::new();
        for contrib in contributions_to_use {
            let id_bytes = hex_to_bytes(&contrib.sender_id)?;
            let id_fr = deserialize_fr(&id_bytes)?;
            let mut bls_id: BlsId = mem::zeroed();
            let id_fr_bytes = serialize_fr(&id_fr);
            let consumed =
                blsIdDeserialize(&mut bls_id, id_fr_bytes.as_ptr() as *const _, id_fr_bytes.len());
            if consumed == 0 {
                return Err("Failed to convert contributor Fr to BlsId".to_string());
            }
            bls_contributor_ids.push(bls_id);
        }

        let first_contrib = &contributions_to_use[0].contribution;
        let pg_count = first_contrib.pg.len();
        let mut recovered_pgs: Vec<mclBnG2> = Vec::new();

        for pg_index in 0..pg_count {
            let mut bls_pgs_at_index: Vec<BlsPublicKey> = Vec::new();

            for contrib in contributions_to_use {
                if contrib.contribution.pg.len() <= pg_index {
                    return Err("Inconsistent PG lengths across contributions".to_string());
                }

                let pg_bytes = hex_to_bytes(&contrib.contribution.pg[pg_index])?;
                let pg = deserialize_g2(&pg_bytes)?;
                let mut bls_pk: BlsPublicKey = mem::zeroed();
                bls_pk.v = pg;
                bls_pgs_at_index.push(bls_pk);
            }

            let mut recovered_pg_bls: BlsPublicKey = mem::zeroed();
            let ret = blsPublicKeyRecover(
                &mut recovered_pg_bls,
                bls_pgs_at_index.as_ptr(),
                bls_contributor_ids.as_ptr(),
                contributions_to_use.len(),
            );
            if ret != 0 {
                return Err(
                    "blsPublicKeyRecover failed for PG in calculate_threshold_keys".to_string(),
                );
            }

            recovered_pgs.push(recovered_pg_bls.v);
        }

        let pg_hex: Vec<String> = recovered_pgs
            .iter()
            .map(|pg| bytes_to_hex(&serialize_g2(pg)))
            .collect();

        Ok(ThresholdKeys {
            actor_id: actor_id.to_string(),
            pg: pg_hex,
        })
    }
}

pub fn generate_actor_share(
    actor_id: &str,
    actor_contract: &ActorContract,
    my_id: &str,
    my_secret_key: &str,
) -> Result<ActorShare, String> {
    let threshold = actor_contract.threshold;
    let all_contributions = &actor_contract.contributions;

    if all_contributions.len() < threshold {
        return Err(format!(
            "Not enough contributions: got {}, need {}",
            all_contributions.len(),
            threshold
        ));
    }

    let contributions = &all_contributions[..threshold];

    unsafe {
        let my_id_bytes = hex_to_bytes(my_id)?;
        let my_id_fr = deserialize_fr(&my_id_bytes)?;

        struct ParticipantData {
            sender_id: mclBnFr,
            decrypted_share: mclBnFr,
            public_share: mclBnG2,
        }

        let mut participants: std::collections::HashMap<String, ParticipantData> =
            std::collections::HashMap::new();

        let _helper_g2 = get_g2_generator();

        let my_sk_bytes = hex_to_bytes(my_secret_key)?;
        let my_sk_fr = deserialize_fr(&my_sk_bytes)?;

        let _my_pk = derive_public_key_g2(&my_sk_fr);

        for contribution in contributions {
            let sender_id_bytes = hex_to_bytes(&contribution.sender_id)?;
            let sender_id = deserialize_fr(&sender_id_bytes)?;

            let my_esh = contribution
                .contribution
                .esh
                .iter()
                .find(|esh| esh.receiver_id == my_id);

            if let Some(my_esh) = my_esh {
                let mut pgs: Vec<mclBnG2> = Vec::new();
                for pg_hex in &contribution.contribution.pg {
                    let pg_bytes = hex_to_bytes(pg_hex)?;
                    let pg = deserialize_g2(&pg_bytes)?;
                    pgs.push(pg);
                }

                let receiver_id_bytes = hex_to_bytes(&my_esh.receiver_id)?;
                let receiver_id = deserialize_fr(&receiver_id_bytes)?;

                if mclBnFr_isEqual(&receiver_id, &my_id_fr) == 0 {
                    return Err("Receiver ID mismatch".to_string());
                }

                let receiver_pk_bytes = hex_to_bytes(&my_esh.receiver_pk)?;
                let receiver_pk = deserialize_g2(&receiver_pk_bytes)?;

                let mut receiver_bls_id: BlsId = mem::zeroed();
                let receiver_id_bytes = serialize_fr(&receiver_id);
                let consumed = blsIdDeserialize(
                    &mut receiver_bls_id,
                    receiver_id_bytes.as_ptr() as *const _,
                    receiver_id_bytes.len(),
                );
                if consumed == 0 {
                    return Err("Failed to convert receiver Fr to BlsId".to_string());
                }

                let mut bls_pks: Vec<BlsPublicKey> = Vec::new();
                for pg in &pgs {
                    let mut bls_pk: BlsPublicKey = mem::zeroed();
                    bls_pk.v = *pg;
                    bls_pks.push(bls_pk);
                }

                let mut public_share_bls: BlsPublicKey = mem::zeroed();
                let ret = blsPublicKeyShare(
                    &mut public_share_bls,
                    bls_pks.as_ptr(),
                    pgs.len(),
                    &receiver_bls_id,
                );
                if ret != 0 {
                    return Err("blsPublicKeyShare failed".to_string());
                }

                let public_share = public_share_bls.v;

                let decrypted_share =
                    pvsh_decode_g2(&receiver_id, &receiver_pk, &my_sk_fr, &my_esh.esh)?;

                participants.insert(
                    contribution.sender_id.clone(),
                    ParticipantData {
                        sender_id,
                        decrypted_share,
                        public_share,
                    },
                );
            }
        }

        if participants.len() < threshold {
            return Err(format!(
                "Not enough decrypted shares: got {}, need {}",
                participants.len(),
                threshold
            ));
        }

        let participant_list: Vec<_> = participants.values().collect();

        let mut bls_ids: Vec<BlsId> = Vec::new();
        for p in &participant_list {
            let mut bls_id: BlsId = mem::zeroed();
            let id_bytes = serialize_fr(&p.sender_id);
            let consumed =
                blsIdDeserialize(&mut bls_id, id_bytes.as_ptr() as *const _, id_bytes.len());
            if consumed == 0 {
                return Err("Failed to convert sender Fr to BlsId".to_string());
            }
            bls_ids.push(bls_id);
        }

        let mut bls_secret_shares: Vec<BlsSecretKey> = Vec::new();
        for p in &participant_list {
            let share_bytes = serialize_fr(&p.decrypted_share);
            let mut bls_sk: BlsSecretKey = mem::zeroed();
            let consumed = blsSecretKeyDeserialize(
                &mut bls_sk,
                share_bytes.as_ptr() as *const _,
                share_bytes.len(),
            );
            if consumed == 0 {
                return Err("Failed to convert decrypted share to BlsSecretKey".to_string());
            }
            bls_secret_shares.push(bls_sk);
        }

        let mut my_recovered_secret_bls: BlsSecretKey = mem::zeroed();
        let ret = blsSecretKeyRecover(
            &mut my_recovered_secret_bls,
            bls_secret_shares.as_ptr(),
            bls_ids.as_ptr(),
            participant_list.len(),
        );
        if ret != 0 {
            return Err("blsSecretKeyRecover failed".to_string());
        }

        let mut secret_bytes = vec![0u8; BLS_SECRET_KEY_SIZE];
        let size = blsSecretKeySerialize(
            secret_bytes.as_mut_ptr() as *mut _,
            BLS_SECRET_KEY_SIZE,
            &my_recovered_secret_bls,
        );
        if size == 0 {
            return Err("Failed to serialize recovered secret".to_string());
        }
        let my_recovered_secret = deserialize_fr(&secret_bytes[..size])?;

        let mut bls_public_shares: Vec<BlsPublicKey> = Vec::new();
        for p in &participant_list {
            let mut bls_pk: BlsPublicKey = mem::zeroed();
            bls_pk.v = p.public_share;
            bls_public_shares.push(bls_pk);
        }

        let mut my_recovered_public_bls: BlsPublicKey = mem::zeroed();
        let ret = blsPublicKeyRecover(
            &mut my_recovered_public_bls,
            bls_public_shares.as_ptr(),
            bls_ids.as_ptr(),
            participant_list.len(),
        );
        if ret != 0 {
            return Err("blsPublicKeyRecover failed".to_string());
        }

        let my_recovered_public = my_recovered_public_bls.v;

        let first_contrib = &contributions[0].contribution;
        let pg_count = first_contrib.pg.len();
        let mut recovered_pgs: Vec<mclBnG2> = Vec::new();

        for pg_index in 0..pg_count {
            let mut bls_pgs_at_index: Vec<BlsPublicKey> = Vec::new();

            for contribution in contributions {
                if contribution.contribution.pg.len() <= pg_index {
                    return Err("Inconsistent PG lengths".to_string());
                }

                let pg_bytes = hex_to_bytes(&contribution.contribution.pg[pg_index])?;
                let pg = deserialize_g2(&pg_bytes)?;
                let mut bls_pk: BlsPublicKey = mem::zeroed();
                bls_pk.v = pg;
                bls_pgs_at_index.push(bls_pk);
            }

            let mut recovered_pg_bls: BlsPublicKey = mem::zeroed();
            let ret = blsPublicKeyRecover(
                &mut recovered_pg_bls,
                bls_pgs_at_index.as_ptr(),
                bls_ids.as_ptr(),
                participant_list.len(),
            );
            if ret != 0 {
                return Err("blsPublicKeyRecover failed for PG".to_string());
            }

            recovered_pgs.push(recovered_pg_bls.v);
        }

        let mut all_phs: Vec<PublicShare> = Vec::new();

        for (sender_id_str, participant) in &participants {
            let ph_hex = bytes_to_hex(&serialize_g2(&participant.public_share));
            all_phs.push(PublicShare {
                id: sender_id_str.clone(),
                ph: ph_hex,
            });
        }

        let pg_hex: Vec<String> = recovered_pgs
            .iter()
            .map(|pg| bytes_to_hex(&serialize_g2(pg)))
            .collect();

        Ok(ActorShare {
            actor_id: actor_id.to_string(),
            share_code: actor_contract.actor_share.share_code.clone(),
            subject_actor_id: actor_contract.actor_share.subject_actor_id.clone(),
            hat_id: actor_contract.actor_share.hat_id.clone(),
            from_actor_id: actor_contract.actor_share.from_actor_id.clone(),
            to_actor_id: actor_contract.actor_share.to_actor_id.clone(),
            owner_actor_id: actor_contract.actor_share.owner_actor_id.clone(),
            pg: pg_hex,
            sh: bytes_to_hex(&serialize_fr(&my_recovered_secret)),
            ph: bytes_to_hex(&serialize_g2(&my_recovered_public)),
            phs: all_phs,
        })
    }
}
