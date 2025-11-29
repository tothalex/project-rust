use crate::types::{VirtualDeviceStorage, SharedDeviceData};
use crate::crypto::{generate_keypair_hex, generate_id_hex};

/// Generate device storage with two key pairs and two IDs
///
/// This is the Rust equivalent of the TypeScript generateDeviceStorage() function.
///
/// # What this does:
/// 1. Generates a main keypair for the device
/// 2. Generates a separate keypair for shared device data
/// 3. Generates two random IDs (one for device, one for shared data)
/// 4. Returns all cryptographic material as hex-encoded strings
///
/// # Arguments
/// * `device_name` - A string name for the device
///
/// # Returns
/// A `VirtualDeviceStorage` struct containing all the generated keys and IDs
pub fn generate_device_storage(device_name: &str) -> VirtualDeviceStorage {
    // Generate main device keypair
    let device_keys = generate_keypair_hex();

    // Generate shared device keypair
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
