use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::Contribution;

/// Custom JSON stringifier that matches TypeScript's JSONConverter behavior
/// Converts numbers to strings with .0 appended (e.g., 2 becomes "2.0")
fn stringify_with_converter(value: &impl Serialize) -> Result<String, serde_json::Error> {
    let json_value = serde_json::to_value(value)?;
    let converted = convert_numbers_to_decimal_strings(&json_value);
    serde_json::to_string(&converted)
}

/// Recursively convert all numbers to strings with .0 appended
fn convert_numbers_to_decimal_strings(value: &Value) -> Value {
    match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::String(format!("{}.0", i))
            } else if let Some(u) = n.as_u64() {
                Value::String(format!("{}.0", u))
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 {
                    Value::String(format!("{}.0", f as i64))
                } else {
                    Value::String(f.to_string())
                }
            } else {
                value.clone()
            }
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(convert_numbers_to_decimal_strings).collect())
        }
        Value::Object(obj) => {
            Value::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), convert_numbers_to_decimal_strings(v)))
                    .collect()
            )
        }
        _ => value.clone(),
    }
}

#[derive(Debug, Serialize)]
struct CreateDeviceRequest {
    name: String,
    id: String,
    pm: String,
    #[serde(rename = "sharedId")]
    shared_id: String,
    #[serde(rename = "sharedPm")]
    shared_pm: String,
    model: String,
    #[serde(rename = "osName")]
    os_name: String,
    #[serde(rename = "osVersion")]
    os_version: String,
    #[serde(rename = "pushToken")]
    push_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContributeDevicePayload {
    contract_id: String,
    sender_id: String,
    contribution: Contribution,
    device_registration_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InitiationContext {
    acting_actor_id: String,
    hat_actor_id: String,
    share_code: String,
    role_code: String,
    owner_actor_id: String,
    subject_actor_id: String,
    instruction_mode: InstructionMode,
    initiation_role: InitiationRole,
}

#[derive(Debug, Serialize)]
struct InstructionMode {
    code: String,
}

#[derive(Debug, Serialize)]
struct InitiationRole {
    code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationRequest {
    payload: ContributeDevicePayload,
    initiation_context: InitiationContext,
    message_id: String,
    url: String,
}

#[derive(Debug, Serialize)]
struct InputOperationRequest {
    data: OperationRequest,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActorShareResponse {
    share_code: String,
    subject_actor_id: Option<String>,
    hat_id: Option<String>,
    from_actor_id: Option<String>,
    role_code: Option<String>,
    to_actor_id: Option<String>,
    owner_actor_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberResponse {
    id: String,
    pm: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActorContractResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    threshold: Option<usize>,
    #[serde(default)]
    new_members: Vec<MemberResponse>,
    #[serde(default)]
    actor_share: Option<ActorShareResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationResponse<T> {
    result: T,
    state: OperationStatus,
    uid: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum OperationStatus {
    Pending,
    Success,
    Error,
    Expired,
}

#[cfg(test)]
mod tests {
    use crate::{generate_contribution, generate_device_storage};

    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test() {
        crate::init_bls();
    }

    #[derive(Debug)]
    struct DeviceStorage {
        name: String,
        id: String,
        pm: String,
        shared_id: String,
        shared_pm: String,
    }

    fn initialize() {
        INIT.call_once(|| {
            init_test();
        });
    }

    #[test]
    fn test_device_registration() -> Result<(), Box<dyn std::error::Error>> {
        initialize();

        let storage = generate_device_storage("Test Device");

        println!("DEBUG: Shared PM (public key): {}", storage.shared_device_data.pm);
        println!("DEBUG: Shared PM length: {} hex chars", storage.shared_device_data.pm.len());

        let create_device_input = CreateDeviceRequest {
            name: storage.name.clone(),
            id: storage.id.clone(),
            pm: storage.pm.clone(),
            shared_id: storage.shared_device_data.id.clone(),
            shared_pm: storage.shared_device_data.pm.clone(),
            model: "Qantrum CLI Device".into(),
            os_name: "Other".to_string(),
            os_version: "1".into(),
            push_token: "pushItToTheLimit".into(),
        };

        let base_url = "http://localhost:3000/api";

        // Step 1: Register device - get actor contract with newMembers
        println!("\n=== Step 1: Registering device ===");
        let actor_contract = ureq::post(&format!("{}/devices", base_url))
            .header("X-My-Header", "Secret")
            .send_json(&create_device_input)?
            .body_mut()
            .read_json::<OperationResponse<ActorContractResponse>>()?;

        let contract_id = actor_contract.result.id.as_ref()
            .ok_or("Missing contract ID")?;
        let threshold = actor_contract.result.threshold
            .ok_or("Missing threshold")?;

        println!("Contract ID: {}", contract_id);
        println!("Threshold: {}", threshold);
        println!("New Members: {}", actor_contract.result.new_members.len());

        for (i, member) in actor_contract.result.new_members.iter().enumerate() {
            println!("  Member {}: {}", i + 1, &member.id[..16]);
        }

        // Step 2: Generate contribution using newMembers
        println!("\n=== Step 2: Generating contribution ===");
        let members: Vec<crate::Member> = actor_contract
            .result
            .new_members
            .iter()
            .map(|m| crate::Member {
                id: m.id.clone(),
                pm: m.pm.clone(),
            })
            .collect();

        let contribution = generate_contribution(threshold, &members)?;

        println!("Generated contribution:");
        println!("  Public generators: {}", contribution.pg.len());
        println!("  Encrypted shares: {}", contribution.esh.len());

        // Step 3: POST contribution back to server
        println!("\n=== Step 3: Sending contribution ===");

        let contribute_url = format!(
            "{}/actor-contracts/{}/contribute-device",
            base_url, contract_id
        );

        let share_code = format!("DEVICEREG_{}", storage.id);

        let operation_request = OperationRequest {
            payload: ContributeDevicePayload {
                contract_id: contract_id.clone(),
                sender_id: storage.id.clone(),
                contribution,
                device_registration_token: storage.shared_device_data.id.clone(),
            },
            initiation_context: InitiationContext {
                acting_actor_id: storage.id.clone(),
                hat_actor_id: storage.shared_device_data.id.clone(),
                share_code,
                role_code: "DEVICEREG".to_string(),
                owner_actor_id: storage.shared_device_data.id.clone(),
                subject_actor_id: storage.shared_device_data.id.clone(),
                instruction_mode: InstructionMode {
                    code: "IN_PERSON".to_string(),
                },
                initiation_role: InitiationRole {
                    code: "OWN_NAME".to_string(),
                },
            },
            message_id: "test-message-id-123".to_string(), // Simplified for test
            url: contribute_url.clone(),
        };

        // Sign the request with the shared device secret key
        // Use custom JSON serialization to match TypeScript JSONConverter
        let data_json = stringify_with_converter(&operation_request)?;

        // Save for debugging
        std::fs::write("/tmp/rust_json_to_sign.json", &data_json)?;
        std::fs::write("/tmp/rust_secret_key.txt", &storage.shared_device_data.sm)?;

        // IMPORTANT: The backend computes SHA-512(JSON) and passes it to verify().
        // The verify() method hashes its input again, so it checks H(SHA-512(JSON)).
        // Therefore, we must sign SHA-512(JSON), not the JSON directly.
        let signature = crate::crypto::sign(
            data_json.as_bytes(),
            &storage.shared_device_data.sm
        )?;

        std::fs::write("/tmp/rust_signature.txt", &signature)?;
        println!("Signature generated: {} hex chars", signature.len());
        println!("Files saved to /tmp/rust_* for debugging");

        let input_operation = InputOperationRequest {
            data: operation_request,
            signature,
        };

        let mut response = ureq::post(&contribute_url)
            .header("X-My-Header", "Secret")
            .send_json(&input_operation)?;

        // First read as Value to see structure
        let response_value: OperationResponse<serde_json::Value> =
            response.body_mut().read_json()?;

        println!("✓ Contribution sent successfully!");

        // The response might be empty, which is OK
        if response_value.result.is_null() || response_value.result.as_object().map(|o| o.is_empty()).unwrap_or(false) {
            println!("(Server acknowledged contribution with empty response)");
        } else {
            println!("Response result:");
            println!("{}", serde_json::to_string_pretty(&response_value.result)?);
        }

        // TODO: Step 4: Generate actor share from final response

        Ok(())
    }
}
