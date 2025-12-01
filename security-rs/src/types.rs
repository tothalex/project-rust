use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedDeviceData {
    pub id: String,
    pub sm: String,
    pub pm: String,
    pub actor_shares: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDeviceStorage {
    pub id: String,
    pub sm: String,
    pub pm: String,
    pub name: String,
    pub shared_device_data: SharedDeviceData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub pm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShare {
    pub receiver_id: String,
    #[serde(rename = "receiverPK")]
    pub receiver_pk: String,
    pub esh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub pg: Vec<String>,
    pub esh: Vec<EncryptedShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedContribution {
    pub sender_id: String,
    pub contribution: Contribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorShareData {
    pub share_code: String,
    pub subject_actor_id: String,
    pub hat_id: String,
    pub from_actor_id: String,
    pub to_actor_id: String,
    pub owner_actor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicShare {
    pub id: String,
    pub ph: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorContract {
    pub threshold: usize,
    pub new_members: Vec<Member>,
    pub contributions: Vec<ReceivedContribution>,
    pub actor_share: ActorShareData,
}

#[derive(Debug, Clone)]
pub struct ThresholdKeys {
    pub actor_id: String,
    pub pg: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorShare {
    pub actor_id: String,
    pub share_code: String,
    pub subject_actor_id: String,
    pub hat_id: String,
    pub from_actor_id: String,
    pub to_actor_id: String,
    pub owner_actor_id: String,
    pub pg: Vec<String>,
    pub sh: String,
    pub ph: String,
    pub phs: Vec<PublicShare>,
}
