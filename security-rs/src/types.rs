use serde::{Deserialize, Serialize};

// ============================================================================
// Key Pair Types
// ============================================================================

/// Represents a BLS key pair with secret and public keys as hex strings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key: String,
    pub public_key: String,
}

// ============================================================================
// Device Storage Types
// ============================================================================

/// Shared device data containing its own ID, keys, and actor shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedDeviceData {
    pub id: String,
    pub sm: String,  // secret key (main) for shared data
    pub pm: String,  // public key (main) for shared data
    pub actor_shares: Vec<String>,
}

/// Virtual device storage containing device identity and cryptographic keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDeviceStorage {
    pub id: String,
    pub sm: String,  // secret key (main)
    pub pm: String,  // public key (main)
    pub name: String,
    pub shared_device_data: SharedDeviceData,
}

// ============================================================================
// Threshold Secret Sharing Types
// ============================================================================

/// Member participating in threshold secret sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: String,   // Member's ID (hex-encoded Fr)
    pub pm: String,   // Member's public key (hex-encoded G2)
}

/// Encrypted Secret Handoff (ESH) - encrypted share for a member
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShare {
    pub receiver_id: String,  // ID of the receiver
    pub receiver_pk: String,  // Public key of the receiver
    pub esh: String,          // Encrypted share (format: "c.U.V")
}

/// Contribution for threshold secret sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub pg: Vec<String>,            // Public generators (hex-encoded G2 public keys)
    pub esh: Vec<EncryptedShare>,   // Encrypted shares for each member
}

/// Received contribution from a sender
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedContribution {
    pub sender_id: String,          // ID of the sender
    pub contribution: Contribution, // The contribution data
}

// ============================================================================
// Actor Share Types
// ============================================================================

/// Actor share data (base structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorShareData {
    pub share_code: String,
    pub subject_actor_id: String,
    pub hat_id: String,
    pub from_actor_id: String,
    pub to_actor_id: String,
    pub owner_actor_id: String,
}

/// Actor role codes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActorRoleCode {
    #[serde(rename = "DEVICEREG")]
    DeviceReg,
}

/// Complete actor share data for a device (extends ActorShareData with crypto keys)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorShareDataDevice {
    pub actor_id: String,
    pub role_code: ActorRoleCode,
    pub share_code: String,
    pub subject_actor_id: String,
    pub hat_id: String,
    pub from_actor_id: String,
    pub to_actor_id: String,
    pub owner_actor_id: String,
    pub pg: String,                      // Public generator (recovered from all contributions)
    pub sh: String,                      // Secret share (my recovered secret)
    pub ph: String,                      // Public share (my recovered public key)
    pub phs: Vec<PublicShare>,           // All participants' public shares
}

/// Public share for a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicShare {
    pub id: String,  // Participant ID
    pub ph: String,  // Participant's public key
}

/// Actor contract containing threshold parameters and shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorContract {
    pub threshold: usize,
    pub new_members: Vec<Member>,
    pub contributions: Vec<ReceivedContribution>,
    pub actor_share: ActorShareData,
}

/// Threshold key result (from calculating threshold keys)
#[derive(Debug, Clone)]
pub struct ThresholdKey {
    pub id: String,      // My ID
    pub sh: String,      // My secret share (hex)
    pub ph: String,      // My public share (hex)
    pub phs: Vec<PublicShare>,  // All public shares
    pub pg: String,      // Public generator (hex)
    pub errors: Vec<ThresholdError>,
}

/// Error during threshold key calculation
#[derive(Debug, Clone)]
pub struct ThresholdError {
    pub sender_id: Option<String>,
    pub receiver_id: String,
    pub reason: String,
}
