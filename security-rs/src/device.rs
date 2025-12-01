use crate::crypto::{generate_id_hex, generate_keypair_hex};
use crate::types::{SharedDeviceData, VirtualDeviceStorage};

pub fn generate_device_storage(device_name: &str) -> VirtualDeviceStorage {
    let device_keys = generate_keypair_hex();
    let shared_device_keys = generate_keypair_hex();

    VirtualDeviceStorage {
        id: generate_id_hex(),
        sm: device_keys.secret_key,
        pm: device_keys.public_key,
        name: device_name.to_string(),
        shared_device_data: SharedDeviceData {
            id: generate_id_hex(),
            sm: shared_device_keys.secret_key,
            pm: shared_device_keys.public_key,
            actor_shares: Vec::new(),
        },
    }
}
