use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::cdp::client::CdpClient;
use super::cdp::types::{
    AttachToTargetParams, AttachToTargetResult, CloseTargetParams, CreateTargetParams,
    CreateTargetResult, EvaluateParams,
};
use super::cookies::{self, Cookie};
use crate::validation::{is_valid_session_name, sanitize_session_component, session_name_error};

const STATE_FORMAT_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateSelection {
    pub cookies: bool,
    pub local_storage: bool,
    pub session_storage: bool,
}

impl StateSelection {
    pub const fn all() -> Self {
        Self {
            cookies: true,
            local_storage: true,
            session_storage: true,
        }
    }

    pub const fn cookies_only() -> Self {
        Self {
            cookies: true,
            local_storage: false,
            session_storage: false,
        }
    }

    pub const fn has_storage(self) -> bool {
        self.local_storage || self.session_storage
    }

    pub fn from_categories(categories: &[StateCategory]) -> Self {
        Self {
            cookies: categories.contains(&StateCategory::Cookies),
            local_storage: categories.contains(&StateCategory::LocalStorage),
            session_storage: categories.contains(&StateCategory::SessionStorage),
        }
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self {
            cookies: self.cookies && other.cookies,
            local_storage: self.local_storage && other.local_storage,
            session_storage: self.session_storage && other.session_storage,
        }
    }

    pub fn categories(self) -> Vec<StateCategory> {
        let mut categories = Vec::new();
        if self.cookies {
            categories.push(StateCategory::Cookies);
        }
        if self.local_storage {
            categories.push(StateCategory::LocalStorage);
        }
        if self.session_storage {
            categories.push(StateCategory::SessionStorage);
        }
        categories
    }
}

impl Default for StateSelection {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateCategory {
    Cookies,
    LocalStorage,
    SessionStorage,
}

pub fn parse_state_selection(value: Option<&Value>) -> Result<StateSelection, String> {
    let Some(value) = value else {
        return Ok(StateSelection::default());
    };
    let names: Vec<&str> = match value {
        Value::String(value) => value.split(',').map(str::trim).collect(),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "State categories must be strings".to_string())
            })
            .collect::<Result<_, _>>()?,
        _ => return Err("State categories must be a string or array".to_string()),
    };
    let mut categories = Vec::new();
    for name in names {
        let category = match name {
            "cookies" => StateCategory::Cookies,
            "local-storage" | "localStorage" => StateCategory::LocalStorage,
            "session-storage" | "sessionStorage" => StateCategory::SessionStorage,
            _ => return Err(format!("Unsupported state category: {}", name)),
        };
        if !categories.contains(&category) {
            categories.push(category);
        }
    }
    Ok(StateSelection::from_categories(&categories))
}

fn is_legacy_format_version(version: &u32) -> bool {
    *version == 0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageState {
    #[serde(default, skip_serializing_if = "is_legacy_format_version")]
    pub format_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<StateCategory>>,
    #[serde(default)]
    pub cookies: Vec<Cookie>,
    #[serde(default)]
    pub origins: Vec<OriginStorage>,
}

impl StorageState {
    pub fn included_selection(&self) -> StateSelection {
        self.categories
            .as_deref()
            .map(StateSelection::from_categories)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginStorage {
    pub origin: String,
    #[serde(default)]
    pub local_storage: Vec<StorageEntry>,
    #[serde(default)]
    pub session_storage: Vec<StorageEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageEntry {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDiffValue {
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDiffEntry {
    pub category: StateCategory,
    pub identity: Value,
    pub value: StateDiffValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDiffChange {
    pub category: StateCategory,
    pub identity: Value,
    pub before: StateDiffValue,
    pub after: StateDiffValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDiff {
    pub redacted: bool,
    pub added: Vec<StateDiffEntry>,
    pub removed: Vec<StateDiffEntry>,
    pub changed: Vec<StateDiffChange>,
}

fn collect_frame_origins(tree: &Value, origins: &mut HashSet<String>) {
    if let Some(frame) = tree.get("frame") {
        if let Some(url_str) = frame.get("url").and_then(|v| v.as_str()) {
            if let Ok(parsed) = url::Url::parse(url_str) {
                let origin = parsed.origin().ascii_serialization();
                if origin != "null" && !origin.is_empty() {
                    origins.insert(origin);
                }
            }
        }
    }
    if let Some(children) = tree.get("childFrames").and_then(|v| v.as_array()) {
        for child in children {
            collect_frame_origins(child, origins);
        }
    }
}

/// Parse the JS-evaluated origin storage data into an OriginStorage struct.
fn parse_origin_storage(data: &Value) -> Option<OriginStorage> {
    if !data.is_object() {
        return None;
    }
    let origin = data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if origin.is_empty() || origin == "null" {
        return None;
    }
    let local_storage: Vec<StorageEntry> = data
        .get("localStorage")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let session_storage: Vec<StorageEntry> = data
        .get("sessionStorage")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    Some(OriginStorage {
        origin,
        local_storage,
        session_storage,
    })
}

/// Evaluate the storage-collection JS snippet and parse the result.
async fn eval_origin_storage(
    client: &CdpClient,
    session_id: &str,
    origin_js: &str,
) -> Option<OriginStorage> {
    let result = client
        .send_command_typed::<_, super::cdp::types::EvaluateResult>(
            "Runtime.evaluate",
            &EvaluateParams {
                expression: origin_js.to_string(),
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(session_id),
        )
        .await
        .ok()?;
    let data = result.result.value.unwrap_or(Value::Null);
    parse_origin_storage(&data)
}

/// Create a temporary CDP target, navigate it to each origin to collect localStorage,
/// then close it. Uses Fetch interception to serve blank HTML instead of making real
/// network requests.
async fn collect_storage_via_temp_target(
    client: &CdpClient,
    origins: &[String],
    origin_js: &str,
) -> Result<Vec<OriginStorage>, String> {
    let create_result: CreateTargetResult = client
        .send_command_typed(
            "Target.createTarget",
            &CreateTargetParams {
                url: "about:blank".to_string(),
            },
            None,
        )
        .await?;

    let target_id = create_result.target_id;

    // Ensure the target is closed even if attach or later steps fail
    let result = collect_storage_in_target(client, &target_id, origins, origin_js).await;

    let _ = client
        .send_command_typed::<_, Value>(
            "Target.closeTarget",
            &CloseTargetParams { target_id },
            None,
        )
        .await;

    result
}

async fn collect_storage_in_target(
    client: &CdpClient,
    target_id: &str,
    origins: &[String],
    origin_js: &str,
) -> Result<Vec<OriginStorage>, String> {
    let attach_result: AttachToTargetResult = client
        .send_command_typed(
            "Target.attachToTarget",
            &AttachToTargetParams {
                target_id: target_id.to_string(),
                flatten: true,
            },
            None,
        )
        .await?;

    let temp_session = &attach_result.session_id;

    client
        .send_command_no_params("Page.enable", Some(temp_session))
        .await?;
    client
        .send_command_no_params("Runtime.enable", Some(temp_session))
        .await?;

    // Blank HTML response body, pre-encoded to avoid repeated base64 work per request
    let blank_html_b64 = base64::engine::general_purpose::STANDARD.encode("<html></html>");

    let _ = client
        .send_command(
            "Fetch.enable",
            Some(json!({ "patterns": [{ "urlPattern": "*" }] })),
            Some(temp_session),
        )
        .await;

    let mut event_rx = client.subscribe();
    let mut results = Vec::new();

    for target_origin in origins {
        let nav_url = format!("{}/", target_origin.trim_end_matches('/'));
        if client
            .send_command(
                "Page.navigate",
                Some(json!({ "url": nav_url })),
                Some(temp_session),
            )
            .await
            .is_err()
        {
            continue;
        }

        // Fulfill intercepted requests with blank HTML until the page loads
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        let mut page_loaded = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(tokio::time::Duration::from_secs(2), event_rx.recv()).await {
                Ok(Ok(evt)) if evt.session_id.as_deref() == Some(temp_session) => {
                    if evt.method == "Fetch.requestPaused" {
                        if let Some(request_id) =
                            evt.params.get("requestId").and_then(|v| v.as_str())
                        {
                            let _ = client
                                .send_command(
                                    "Fetch.fulfillRequest",
                                    Some(json!({
                                        "requestId": request_id,
                                        "responseCode": 200,
                                        "responseHeaders": [
                                            { "name": "Content-Type", "value": "text/html" }
                                        ],
                                        "body": &blank_html_b64
                                    })),
                                    Some(temp_session),
                                )
                                .await;
                        }
                    } else if evt.method == "Page.loadEventFired" {
                        page_loaded = true;
                        break;
                    }
                }
                Ok(Ok(_)) => continue,  // event for a different session
                Ok(Err(_)) => continue, // lagged or closed — retry within deadline
                Err(_) => break,        // outer timeout elapsed
            }
        }

        if !page_loaded {
            continue;
        }

        if let Some(storage) = eval_origin_storage(client, temp_session, origin_js).await {
            if !storage.local_storage.is_empty() || !storage.session_storage.is_empty() {
                results.push(storage);
            }
        }
    }

    Ok(results)
}

pub async fn save_state(
    client: &CdpClient,
    session_id: &str,
    path: Option<&str>,
    session_name: Option<&str>,
    session_id_str: &str,
    visited_origins: &HashSet<String>,
) -> Result<String, String> {
    save_state_selected(
        client,
        session_id,
        path,
        session_name,
        session_id_str,
        visited_origins,
        StateSelection::default(),
    )
    .await
}

pub async fn save_state_selected(
    client: &CdpClient,
    session_id: &str,
    path: Option<&str>,
    session_name: Option<&str>,
    session_id_str: &str,
    visited_origins: &HashSet<String>,
    selection: StateSelection,
) -> Result<String, String> {
    let cookies = if selection.cookies {
        cookies::get_all_cookies(client, session_id).await?
    } else {
        Vec::new()
    };

    // Cookies-only capture deliberately returns before any frame or storage CDP calls.
    let origins = if selection.has_storage() {
        collect_selected_storage(client, session_id, visited_origins, selection).await
    } else {
        Vec::new()
    };

    let state = StorageState {
        format_version: STATE_FORMAT_VERSION,
        categories: Some(selection.categories()),
        cookies,
        origins,
    };
    write_captured_state(&state, path, session_name, session_id_str)
}

async fn collect_selected_storage(
    client: &CdpClient,
    session_id: &str,
    visited_origins: &HashSet<String>,
    selection: StateSelection,
) -> Vec<OriginStorage> {
    let collect_local = if selection.local_storage {
        "true"
    } else {
        "false"
    };
    let collect_session = if selection.session_storage {
        "true"
    } else {
        "false"
    };

    let origin_js = r#"(() => {
        const result = { origin: location.origin, localStorage: [], sessionStorage: [] };
        if ($COLLECT_LOCAL) try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                result.localStorage.push({ name: key, value: localStorage.getItem(key) });
            }
        } catch(e) {}
        if ($COLLECT_SESSION) try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                result.sessionStorage.push({ name: key, value: sessionStorage.getItem(key) });
            }
        } catch(e) {}
        return result;
    })()"#
        .replace("$COLLECT_LOCAL", collect_local)
        .replace("$COLLECT_SESSION", collect_session);

    // localStorage is shared by origin, so it can be collected from disposable targets.
    // sessionStorage stays scoped to the active top-level browsing context.
    let mut all_origins = HashSet::new();
    if selection.local_storage {
        all_origins.clone_from(visited_origins);
        if let Ok(tree_result) = client
            .send_command_no_params("Page.getFrameTree", Some(session_id))
            .await
        {
            if let Some(tree) = tree_result.get("frameTree") {
                collect_frame_origins(tree, &mut all_origins);
            }
        }
    }

    // 1. Collect localStorage from the current page
    let mut origins = Vec::new();
    let mut current_origin = String::new();

    if let Some(storage) = eval_origin_storage(client, session_id, &origin_js).await {
        current_origin = storage.origin.clone();
        if !storage.local_storage.is_empty() || !storage.session_storage.is_empty() {
            origins.push(storage);
        }
    }

    // 2. Collect localStorage from remaining origins via a disposable temp target
    all_origins.remove(&current_origin);
    if selection.local_storage && !all_origins.is_empty() {
        let remaining: Vec<String> = all_origins.into_iter().collect();
        if let Ok(temp_origins) =
            collect_storage_via_temp_target(client, &remaining, &origin_js).await
        {
            origins.extend(temp_origins);
        }
    }

    origins
}

fn write_captured_state(
    state: &StorageState,
    path: Option<&str>,
    session_name: Option<&str>,
    session_id_str: &str,
) -> Result<String, String> {
    let json_str = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("Failed to serialize state: {}", e))?;

    let mut save_path = match path {
        Some(p) => p.to_string(),
        None => {
            let dir = get_sessions_dir();
            let _ = fs::create_dir_all(&dir);
            let name = session_name.unwrap_or("default");
            if !is_valid_session_name(name) {
                return Err(session_name_error(name));
            }
            dir.join(format!("{}-{}.json", name, session_id_str))
                .to_string_lossy()
                .to_string()
        }
    };

    if let Ok(key) = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY") {
        let encrypted = encrypt_data(json_str.as_bytes(), &key)?;
        save_path.push_str(".enc");
        write_private_state_file(Path::new(&save_path), &encrypted)?;
    } else {
        write_private_state_file(Path::new(&save_path), json_str.as_bytes())?;
    }

    Ok(save_path)
}

pub async fn save_auto_state_transactional(
    client: &CdpClient,
    session_id: &str,
    session_name: &str,
    session_id_str: &str,
    visited_origins: &HashSet<String>,
) -> Result<String, String> {
    if !is_valid_session_name(session_name) {
        return Err(session_name_error(session_name));
    }

    let dir = get_sessions_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create state directory {}: {}", dir.display(), e))?;

    let tmp_dir = dir.join(".tmp");
    fs::create_dir_all(&tmp_dir).map_err(|e| {
        format!(
            "Failed to create temporary state directory {}: {}",
            tmp_dir.display(),
            e
        )
    })?;

    let base_name = format!("{}-{}", session_name, session_id_str);
    let final_json_path = dir.join(format!("{}.json", base_name));
    let final_path = if std::env::var("AGENT_BROWSER_ENCRYPTION_KEY").is_ok() {
        PathBuf::from(format!("{}.enc", final_json_path.to_string_lossy()))
    } else {
        final_json_path
    };
    let candidate_json_path = tmp_dir.join(format!(
        "{}-candidate-{}.json",
        base_name,
        std::process::id()
    ));
    let candidate_arg = candidate_json_path.to_string_lossy().to_string();

    let candidate_path = save_state(
        client,
        session_id,
        Some(&candidate_arg),
        Some(session_name),
        session_id_str,
        visited_origins,
    )
    .await?;

    if let Err(err) = validate_state_file(&candidate_path) {
        let _ = fs::remove_file(&candidate_path);
        return Err(err);
    }

    let previous_path = PathBuf::from(format!("{}.previous", final_path.to_string_lossy()));
    if final_path.exists() {
        let _ = fs::remove_file(&previous_path);
        fs::rename(&final_path, &previous_path).map_err(|e| {
            format!(
                "Failed to rotate previous state {} to {}: {}",
                final_path.display(),
                previous_path.display(),
                e
            )
        })?;
    }

    let candidate = PathBuf::from(&candidate_path);
    if let Err(err) = fs::rename(&candidate, &final_path) {
        if previous_path.exists() && !final_path.exists() {
            let _ = fs::rename(&previous_path, &final_path);
        }
        return Err(format!(
            "Failed to promote state {} to {}: {}",
            candidate.display(),
            final_path.display(),
            err
        ));
    }
    if previous_path.exists() {
        let _ = fs::remove_file(&previous_path);
    }

    Ok(final_path.to_string_lossy().to_string())
}

fn read_state_json(path: &str) -> Result<String, String> {
    if is_encrypted_state(std::path::Path::new(path)) {
        let key = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY").map_err(|_| {
            "Encrypted state file requires AGENT_BROWSER_ENCRYPTION_KEY".to_string()
        })?;
        let data =
            fs::read(path).map_err(|e| format!("Failed to read state from {}: {}", path, e))?;
        let decrypted = decrypt_data(&data, &key)?;
        Ok(String::from_utf8(decrypted)
            .map_err(|e| format!("Decrypted state is not valid UTF-8: {}", e))?)
    } else {
        match fs::read_to_string(path) {
            Ok(s) => Ok(s),
            Err(e) => {
                if let Ok(key) = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY") {
                    let enc_path = format!("{}.enc", path);
                    if let Ok(data) = fs::read(&enc_path) {
                        let decrypted = decrypt_data(&data, &key)?;
                        Ok(String::from_utf8(decrypted)
                            .map_err(|de| format!("Decrypted state is not valid UTF-8: {}", de))?)
                    } else {
                        Err(format!("Failed to read state from {}: {}", path, e))
                    }
                } else {
                    Err(format!("Failed to read state from {}: {}", path, e))
                }
            }
        }
    }
}

pub fn validate_state_file(path: &str) -> Result<(), String> {
    read_storage_state(path)?;
    Ok(())
}

pub async fn load_state(client: &CdpClient, session_id: &str, path: &str) -> Result<(), String> {
    load_state_selected(client, session_id, path, StateSelection::default()).await
}

pub async fn load_state_selected(
    client: &CdpClient,
    session_id: &str,
    path: &str,
    selection: StateSelection,
) -> Result<(), String> {
    let state = read_storage_state(path)?;
    let selection = selection.intersection(state.included_selection());

    if selection.cookies && !state.cookies.is_empty() {
        let cookie_values: Vec<Value> = state
            .cookies
            .iter()
            .map(cookies::to_set_cookie_value)
            .collect();
        cookies::set_cookies(client, session_id, cookie_values, None).await?;
    }

    for origin in &state.origins {
        let has_local_storage = selection.local_storage && !origin.local_storage.is_empty();
        let has_session_storage = selection.session_storage && !origin.session_storage.is_empty();
        if !has_local_storage && !has_session_storage {
            continue;
        }

        // Navigate to origin to set storage
        let navigate_url = format!("{}/", origin.origin.trim_end_matches('/'));
        client
            .send_command(
                "Page.navigate",
                Some(json!({ "url": navigate_url })),
                Some(session_id),
            )
            .await?;

        // Brief wait for navigation
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        if selection.local_storage {
            for entry in &origin.local_storage {
                let js = format!(
                    "localStorage.setItem({}, {})",
                    serde_json::to_string(&entry.name).unwrap_or_default(),
                    serde_json::to_string(&entry.value).unwrap_or_default(),
                );
                let _ = client
                    .send_command_typed::<_, super::cdp::types::EvaluateResult>(
                        "Runtime.evaluate",
                        &EvaluateParams {
                            expression: js,
                            return_by_value: Some(true),
                            await_promise: Some(false),
                        },
                        Some(session_id),
                    )
                    .await;
            }
        }

        if selection.session_storage {
            for entry in &origin.session_storage {
                let js = format!(
                    "sessionStorage.setItem({}, {})",
                    serde_json::to_string(&entry.name).unwrap_or_default(),
                    serde_json::to_string(&entry.value).unwrap_or_default(),
                );
                let _ = client
                    .send_command_typed::<_, super::cdp::types::EvaluateResult>(
                        "Runtime.evaluate",
                        &EvaluateParams {
                            expression: js,
                            return_by_value: Some(true),
                            await_promise: Some(false),
                        },
                        Some(session_id),
                    )
                    .await;
            }
        }
    }

    Ok(())
}

pub fn read_storage_state(path: &str) -> Result<StorageState, String> {
    let json_str = read_state_json(path)?;
    let state: StorageState =
        serde_json::from_str(&json_str).map_err(|e| format!("Invalid state file: {}", e))?;
    if state.format_version > STATE_FORMAT_VERSION {
        return Err(format!(
            "Unsupported state format version {}; this build supports up to {}",
            state.format_version, STATE_FORMAT_VERSION
        ));
    }
    Ok(state)
}

pub fn filter_storage_state(state: &StorageState, selection: StateSelection) -> StorageState {
    let selection = selection.intersection(state.included_selection());
    let origins = if selection.has_storage() {
        state
            .origins
            .iter()
            .filter_map(|origin| {
                let local_storage = if selection.local_storage {
                    origin.local_storage.clone()
                } else {
                    Vec::new()
                };
                let session_storage = if selection.session_storage {
                    origin.session_storage.clone()
                } else {
                    Vec::new()
                };
                if local_storage.is_empty() && session_storage.is_empty() {
                    None
                } else {
                    Some(OriginStorage {
                        origin: origin.origin.clone(),
                        local_storage,
                        session_storage,
                    })
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    StorageState {
        format_version: STATE_FORMAT_VERSION,
        categories: Some(selection.categories()),
        cookies: if selection.cookies {
            state.cookies.clone()
        } else {
            Vec::new()
        },
        origins,
    }
}

/// Clone selected state into a new mode-0600 file without overwriting an existing path.
pub fn clone_state_file_filtered(
    source: &str,
    destination: &str,
    selection: StateSelection,
) -> Result<String, String> {
    let source_path = fs::canonicalize(source)
        .map_err(|e| format!("Failed to resolve state file {}: {}", source, e))?;
    let destination_path = Path::new(destination);
    if destination_path.exists() {
        return Err(format!(
            "Refusing to overwrite existing state file: {}",
            destination
        ));
    }
    if destination_path
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .as_ref()
        .is_some_and(|parent| {
            parent.join(destination_path.file_name().unwrap_or_default()) == source_path
        })
    {
        return Err("Source and destination state files must differ".to_string());
    }

    let state = read_storage_state(source)?;
    let filtered = filter_storage_state(&state, selection);
    let json = serde_json::to_vec_pretty(&filtered)
        .map_err(|e| format!("Failed to serialize state: {}", e))?;
    let bytes = if is_encrypted_state(destination_path) {
        let key = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY").map_err(|_| {
            "Encrypted state file requires AGENT_BROWSER_ENCRYPTION_KEY".to_string()
        })?;
        encrypt_data(&json, &key)?
    } else {
        json
    };

    write_new_private_file(destination_path, &bytes)?;
    Ok(destination.to_string())
}

pub fn filter_state_file(
    source: &str,
    destination: &str,
    selection: StateSelection,
) -> Result<String, String> {
    clone_state_file_filtered(source, destination, selection)
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("Failed to create state file {}: {}", path.display(), e))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!(
            "Failed to write state file {}: {}",
            path.display(),
            error
        ));
    }
    Ok(())
}

fn write_private_state_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(format!(
            "Refusing to write state through symlink: {}",
            path.display()
        ));
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create state directory {}: {}",
                parent.display(),
                error
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
                format!(
                    "Failed to secure state directory {}: {}",
                    parent.display(),
                    error
                )
            })?;
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Failed to write state to {}: {}", path.display(), error))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("Failed to write state to {}: {}", path.display(), error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Failed to secure state {}: {}", path.display(), error))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
struct SemanticStateEntry {
    category: StateCategory,
    identity: Value,
    value: Value,
}

pub fn diff_state_files(
    before_path: &str,
    after_path: &str,
    selection: StateSelection,
    show_values: bool,
) -> Result<StateDiff, String> {
    let before = read_storage_state(before_path)?;
    let after = read_storage_state(after_path)?;
    Ok(diff_storage_states(&before, &after, selection, show_values))
}

pub fn state_diff(
    before_path: &str,
    after_path: &str,
    show_values: bool,
) -> Result<StateDiff, String> {
    diff_state_files(
        before_path,
        after_path,
        StateSelection::default(),
        show_values,
    )
}

pub fn diff_storage_states(
    before: &StorageState,
    after: &StorageState,
    selection: StateSelection,
    show_values: bool,
) -> StateDiff {
    let before = semantic_entries(before, selection);
    let after = semantic_entries(after, selection);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for (key, entry) in &before {
        match after.get(key) {
            None => removed.push(StateDiffEntry {
                category: entry.category,
                identity: entry.identity.clone(),
                value: state_diff_value(&entry.value, show_values),
            }),
            Some(next) if entry.value != next.value => changed.push(StateDiffChange {
                category: entry.category,
                identity: entry.identity.clone(),
                before: state_diff_value(&entry.value, show_values),
                after: state_diff_value(&next.value, show_values),
            }),
            Some(_) => {}
        }
    }

    for (key, entry) in &after {
        if !before.contains_key(key) {
            added.push(StateDiffEntry {
                category: entry.category,
                identity: entry.identity.clone(),
                value: state_diff_value(&entry.value, show_values),
            });
        }
    }

    StateDiff {
        redacted: !show_values,
        added,
        removed,
        changed,
    }
}

fn semantic_entries(
    state: &StorageState,
    selection: StateSelection,
) -> BTreeMap<String, SemanticStateEntry> {
    let selection = selection.intersection(state.included_selection());
    let mut entries = BTreeMap::new();

    if selection.cookies {
        for cookie in &state.cookies {
            let identity = json!({
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "partitionKey": cookie.partition_key,
            });
            let value = json!({
                "value": cookie.value,
                "expires": cookie.expires,
                "httpOnly": cookie.http_only,
                "secure": cookie.secure,
                "sameSite": cookie.same_site,
                "priority": cookie.priority,
                "sameParty": cookie.same_party,
                "sourceScheme": cookie.source_scheme,
                "sourcePort": cookie.source_port,
            });
            insert_semantic_entry(&mut entries, StateCategory::Cookies, identity, value);
        }
    }

    for origin in &state.origins {
        if selection.local_storage {
            for entry in &origin.local_storage {
                let identity = json!({ "origin": origin.origin, "name": entry.name });
                insert_semantic_entry(
                    &mut entries,
                    StateCategory::LocalStorage,
                    identity,
                    Value::String(entry.value.clone()),
                );
            }
        }
        if selection.session_storage {
            for entry in &origin.session_storage {
                let identity = json!({ "origin": origin.origin, "name": entry.name });
                insert_semantic_entry(
                    &mut entries,
                    StateCategory::SessionStorage,
                    identity,
                    Value::String(entry.value.clone()),
                );
            }
        }
    }

    entries
}

fn insert_semantic_entry(
    entries: &mut BTreeMap<String, SemanticStateEntry>,
    category: StateCategory,
    identity: Value,
    value: Value,
) {
    let identity_json = serde_json::to_string(&identity).unwrap_or_default();
    let key = format!("{:?}:{}", category, identity_json);
    entries.insert(
        key,
        SemanticStateEntry {
            category,
            identity,
            value,
        },
    );
}

fn state_diff_value(value: &Value, show_values: bool) -> StateDiffValue {
    let canonical = serde_json::to_vec(value).unwrap_or_default();
    let fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
    StateDiffValue {
        fingerprint,
        value: show_values.then(|| value.clone()),
    }
}

fn is_state_file(path: &std::path::Path) -> bool {
    let fname = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    fname.ends_with(".json")
        || fname.ends_with(".json.enc")
        || fname.ends_with(".json.previous")
        || fname.ends_with(".json.enc.previous")
}

fn is_encrypted_state(path: &std::path::Path) -> bool {
    let path = path.to_string_lossy();
    path.ends_with(".json.enc") || path.ends_with(".json.enc.previous")
}

pub fn state_list() -> Result<Value, String> {
    let dir = get_sessions_dir();
    if !dir.exists() {
        return Ok(json!({ "files": [], "directory": dir.to_string_lossy() }));
    }

    let mut files = Vec::new();

    let entries = fs::read_dir(&dir).map_err(|e| format!("Failed to read sessions dir: {}", e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if is_state_file(&path) {
            let metadata = fs::metadata(&path).ok();
            let filename = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = metadata
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let encrypted = is_encrypted_state(&path);

            files.push(json!({
                "filename": filename,
                "path": path.to_string_lossy(),
                "size": size,
                "modified": modified,
                "encrypted": encrypted,
            }));
        }
    }

    Ok(json!({ "files": files, "directory": dir.to_string_lossy() }))
}

pub fn state_show(path: &str) -> Result<Value, String> {
    let encrypted = is_encrypted_state(std::path::Path::new(path));
    let json_str = if encrypted {
        let key = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY").map_err(|_| {
            "Encrypted state file requires AGENT_BROWSER_ENCRYPTION_KEY".to_string()
        })?;
        let data = fs::read(path).map_err(|e| format!("Failed to read state file: {}", e))?;
        let decrypted = decrypt_data(&data, &key)?;
        String::from_utf8(decrypted)
            .map_err(|e| format!("Decrypted state is not valid UTF-8: {}", e))?
    } else {
        fs::read_to_string(path).map_err(|e| format!("Failed to read state file: {}", e))?
    };

    let state: StorageState =
        serde_json::from_str(&json_str).map_err(|e| format!("Invalid state file: {}", e))?;

    let metadata = fs::metadata(path).ok();
    let filename = std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    Ok(json!({
        "filename": filename,
        "path": path,
        "size": metadata.as_ref().map(|m| m.len()).unwrap_or(0),
        "modified": metadata.as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "encrypted": encrypted,
        "summary": format!("{} cookies, {} origins", state.cookies.len(), state.origins.len()),
        "state": state,
    }))
}

pub fn state_clear(path: Option<&str>) -> Result<Value, String> {
    if let Some(p) = path {
        fs::remove_file(p).map_err(|e| format!("Failed to delete state: {}", e))?;
        return Ok(json!({ "deleted": p }));
    }

    let dir = get_sessions_dir();
    if !dir.exists() {
        return Ok(json!({ "deleted": 0 }));
    }

    let mut count = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_state_file(&path) {
                let _ = fs::remove_file(&path);
                count += 1;
            }
        }
    }

    Ok(json!({ "deleted": count }))
}

pub fn state_clean(max_age_days: u64) -> Result<Value, String> {
    let dir = get_sessions_dir();
    if !dir.exists() {
        return Ok(json!({ "cleaned": 0, "keptCount": 0, "days": max_age_days }));
    }

    let now = std::time::SystemTime::now();
    let max_age = std::time::Duration::from_secs(max_age_days * 86400);
    let mut deleted = 0;
    let mut kept = 0;

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_state_file(&path) {
                continue;
            }

            if let Ok(metadata) = fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(age) = now.duration_since(modified) {
                        if age > max_age {
                            let _ = fs::remove_file(&path);
                            deleted += 1;
                            continue;
                        }
                    }
                }
            }
            kept += 1;
        }
    }

    Ok(json!({ "cleaned": deleted, "keptCount": kept, "days": max_age_days }))
}

pub fn state_rename(old_path: &str, new_name: &str) -> Result<Value, String> {
    let old = PathBuf::from(old_path);
    if !old.exists() {
        return Err(format!("State file not found: {}", old_path));
    }

    let fallback = PathBuf::from(".");
    let dir = old.parent().unwrap_or(&fallback);
    let new_path = dir.join(format!("{}.json", new_name));

    fs::rename(&old, &new_path).map_err(|e| format!("Failed to rename state: {}", e))?;

    Ok(json!({
        "renamed": true,
        "from": old_path,
        "to": new_path.to_string_lossy(),
    }))
}

fn encrypt_data(data: &[u8], key_str: &str) -> Result<Vec<u8>, String> {
    let mut hasher = Sha256::new();
    hasher.update(key_str.as_bytes());
    let key_bytes = hasher.finalize();
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("Invalid key: {}", e))?;

    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("Failed to generate nonce: {}", e))?;
    let ciphertext = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_data(data: &[u8], key_str: &str) -> Result<Vec<u8>, String> {
    if data.len() < 13 {
        return Err("Ciphertext too short".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);

    let mut hasher = Sha256::new();
    hasher.update(key_str.as_bytes());
    let key_bytes = hasher.finalize();
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("Invalid key: {}", e))?;
    let plaintext = cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    Ok(plaintext)
}

pub fn find_auto_state_file(session_name: &str) -> Option<String> {
    if !is_valid_session_name(session_name) {
        return None;
    }

    let dir = get_sessions_dir();
    if !dir.exists() {
        return None;
    }
    let prefix = format!("{}-", session_name);
    let mut best_path: Option<(String, std::time::SystemTime)> = None;

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let fname = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let is_match = fname.starts_with(&prefix)
                && (fname.ends_with(".json") || fname.ends_with(".json.enc"));
            if !is_match {
                continue;
            }
            let modified = fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            if best_path.as_ref().is_none_or(|(_, t)| modified > *t) {
                best_path = Some((path.to_string_lossy().to_string(), modified));
            }
        }
    }
    best_path.map(|(p, _)| p)
}

/// Dispatch a state management command from its JSON payload.
/// Returns `Some(result)` for recognised state_* actions, `None` otherwise.
pub fn dispatch_state_command(cmd: &Value) -> Option<Result<Value, String>> {
    let action = cmd.get("action").and_then(|v| v.as_str())?;
    match action {
        "state_list" => Some(state_list()),
        "state_show" => Some(
            cmd.get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' parameter".to_string())
                .and_then(state_show),
        ),
        "state_clear" => {
            let path = cmd.get("path").and_then(|v| v.as_str());
            Some(state_clear(path))
        }
        "state_clean" => {
            let days = cmd.get("days").and_then(|v| v.as_u64()).unwrap_or(30);
            Some(state_clean(days))
        }
        "state_rename" => Some(
            cmd.get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' parameter".to_string())
                .and_then(|path| {
                    cmd.get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Missing 'name' parameter".to_string())
                        .and_then(|name| state_rename(path, name))
                }),
        ),
        "state_clone" => Some(
            cmd.get("source")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'source' parameter".to_string())
                .and_then(|source| {
                    cmd.get("destination")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Missing 'destination' parameter".to_string())
                        .and_then(|destination| {
                            parse_state_selection(cmd.get("categories")).and_then(|selection| {
                                clone_state_file_filtered(source, destination, selection).map(
                                    |path| {
                                        json!({
                                            "cloned": true,
                                            "source": source,
                                            "path": path,
                                            "categories": selection.categories(),
                                        })
                                    },
                                )
                            })
                        })
                }),
        ),
        "state_diff" => Some(
            cmd.get("left")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'left' parameter".to_string())
                .and_then(|left| {
                    cmd.get("right")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Missing 'right' parameter".to_string())
                        .and_then(|right| {
                            parse_state_selection(cmd.get("categories")).and_then(|selection| {
                                diff_state_files(
                                    left,
                                    right,
                                    selection,
                                    cmd.get("showValues")
                                        .and_then(Value::as_bool)
                                        .unwrap_or(false),
                                )
                                .and_then(|diff| {
                                    serde_json::to_value(diff).map_err(|e| {
                                        format!("Failed to serialize state diff: {}", e)
                                    })
                                })
                            })
                        })
                }),
        ),
        _ => None,
    }
}

/// Return the agent-browser state root (`~/.agent-browser`, falling back to
/// `<tempdir>/agent-browser` when the home directory can't be resolved).
/// This is the parent of `sessions/`, auth storage, and the encryption key.
pub fn get_state_dir() -> PathBuf {
    let base = if let Some(home) = dirs::home_dir() {
        home.join(".agent-browser")
    } else {
        std::env::temp_dir().join("agent-browser")
    };

    if let Ok(namespace) = std::env::var("AGENT_BROWSER_NAMESPACE") {
        let namespace = sanitize_session_component(&namespace);
        if !namespace.is_empty() {
            return base.join("namespaces").join(namespace).join("state");
        }
    }

    base
}

pub fn get_sessions_dir() -> PathBuf {
    get_state_dir().join("sessions")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cookie(name: &str, value: &str) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: 0.0,
            size: name.len() as i64 + value.len() as i64,
            http_only: true,
            secure: true,
            session: true,
            same_site: Some("Lax".to_string()),
            priority: Some("High".to_string()),
            same_party: None,
            source_scheme: Some("Secure".to_string()),
            source_port: Some(443),
            partition_key: None,
            partition_key_opaque: None,
        }
    }

    fn test_state() -> StorageState {
        StorageState {
            format_version: STATE_FORMAT_VERSION,
            categories: Some(StateSelection::all().categories()),
            cookies: vec![test_cookie("session", "cookie-secret")],
            origins: vec![OriginStorage {
                origin: "https://example.com".to_string(),
                local_storage: vec![StorageEntry {
                    name: "local-key".to_string(),
                    value: "local-secret".to_string(),
                }],
                session_storage: vec![StorageEntry {
                    name: "session-key".to_string(),
                    value: "session-secret".to_string(),
                }],
            }],
        }
    }

    #[test]
    fn test_storage_state_serialization() {
        let state = StorageState {
            format_version: STATE_FORMAT_VERSION,
            categories: Some(StateSelection::all().categories()),
            cookies: vec![Cookie {
                name: "session".to_string(),
                value: "abc123".to_string(),
                domain: ".example.com".to_string(),
                path: "/".to_string(),
                expires: 0.0,
                size: 0,
                http_only: true,
                secure: false,
                session: true,
                same_site: Some("Lax".to_string()),
                priority: None,
                same_party: None,
                source_scheme: None,
                source_port: None,
                partition_key: None,
                partition_key_opaque: None,
            }],
            origins: vec![OriginStorage {
                origin: "https://example.com".to_string(),
                local_storage: vec![StorageEntry {
                    name: "key".to_string(),
                    value: "val".to_string(),
                }],
                session_storage: vec![],
            }],
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: StorageState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cookies.len(), 1);
        assert_eq!(parsed.cookies[0].name, "session");
        assert_eq!(parsed.origins.len(), 1);
        assert_eq!(parsed.origins[0].local_storage.len(), 1);
    }

    #[test]
    fn test_storage_state_empty() {
        let state = StorageState {
            format_version: STATE_FORMAT_VERSION,
            categories: Some(StateSelection::all().categories()),
            cookies: vec![],
            origins: vec![],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: StorageState = serde_json::from_str(&json).unwrap();
        assert!(parsed.cookies.is_empty());
        assert!(parsed.origins.is_empty());
    }

    #[test]
    fn test_legacy_state_file_is_accepted_without_metadata() {
        let legacy = r#"{
            "cookies": [{
                "name": "session",
                "value": "legacy-secret",
                "domain": ".example.com",
                "path": "/",
                "httpOnly": true,
                "secure": true,
                "session": true
            }],
            "origins": [{
                "origin": "https://example.com",
                "localStorage": [{"name": "key", "value": "value"}]
            }]
        }"#;

        let state: StorageState = serde_json::from_str(legacy).unwrap();

        assert_eq!(state.format_version, 0);
        assert_eq!(state.categories, None);
        assert_eq!(state.cookies[0].priority, None);
        assert!(state.origins[0].session_storage.is_empty());
    }

    #[test]
    fn test_filter_storage_state_keeps_only_selected_categories() {
        let state = test_state();

        let filtered = filter_storage_state(&state, StateSelection::cookies_only());

        assert_eq!(filtered.format_version, STATE_FORMAT_VERSION);
        assert_eq!(filtered.categories, Some(vec![StateCategory::Cookies]));
        assert_eq!(filtered.cookies.len(), 1);
        assert!(filtered.origins.is_empty());
        assert_eq!(state.origins[0].local_storage[0].value, "local-secret");

        let local_only = filter_storage_state(
            &state,
            StateSelection {
                cookies: false,
                local_storage: true,
                session_storage: false,
            },
        );
        assert!(local_only.cookies.is_empty());
        assert_eq!(local_only.origins[0].local_storage.len(), 1);
        assert!(local_only.origins[0].session_storage.is_empty());
    }

    #[test]
    fn test_parse_state_selection_accepts_cli_and_json_forms() {
        assert_eq!(
            parse_state_selection(Some(&json!("cookies,session-storage"))).unwrap(),
            StateSelection {
                cookies: true,
                local_storage: false,
                session_storage: true,
            }
        );
        assert_eq!(
            parse_state_selection(Some(&json!(["local-storage"]))).unwrap(),
            StateSelection {
                cookies: false,
                local_storage: true,
                session_storage: false,
            }
        );
        assert!(parse_state_selection(Some(&json!("indexed-db"))).is_err());
    }

    #[test]
    fn test_filtered_file_clone_is_private_and_refuses_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.json");
        let destination = directory.path().join("destination.json");
        fs::write(&source, serde_json::to_vec(&test_state()).unwrap()).unwrap();

        clone_state_file_filtered(
            source.to_str().unwrap(),
            destination.to_str().unwrap(),
            StateSelection::cookies_only(),
        )
        .unwrap();

        let cloned = read_storage_state(destination.to_str().unwrap()).unwrap();
        assert_eq!(cloned.cookies.len(), 1);
        assert!(cloned.origins.is_empty());
        assert!(clone_state_file_filtered(
            source.to_str().unwrap(),
            destination.to_str().unwrap(),
            StateSelection::all(),
        )
        .unwrap_err()
        .contains("Refusing to overwrite"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn test_state_diff_is_order_independent() {
        let mut before = test_state();
        before.cookies.push(test_cookie("other", "same"));
        before.origins[0].local_storage.push(StorageEntry {
            name: "unchanged".to_string(),
            value: "same".to_string(),
        });

        let mut after = before.clone();
        after.cookies.reverse();
        after.origins[0].local_storage.reverse();
        after
            .cookies
            .iter_mut()
            .find(|cookie| cookie.name == "session")
            .unwrap()
            .value = "new-cookie-secret".to_string();

        let first = diff_storage_states(&before, &after, StateSelection::all(), false);
        before.cookies.reverse();
        before.origins[0].local_storage.reverse();
        after.cookies.reverse();
        after.origins[0].local_storage.reverse();
        let second = diff_storage_states(&before, &after, StateSelection::all(), false);

        assert_eq!(first, second);
        assert_eq!(first.changed.len(), 1);
        assert_eq!(first.changed[0].category, StateCategory::Cookies);
        let json = serde_json::to_string(&first).unwrap();
        assert!(!json.contains("cookie-secret"));
        assert!(!json.contains("new-cookie-secret"));
    }

    #[test]
    fn test_state_diff_redacts_values_by_default() {
        let before = test_state();
        let mut after = before.clone();
        after.origins[0].local_storage[0].value = "changed-secret".to_string();

        let redacted = diff_storage_states(&before, &after, StateSelection::all(), false);
        let redacted_json = serde_json::to_string(&redacted).unwrap();
        assert!(redacted.redacted);
        assert!(!redacted_json.contains("local-secret"));
        assert!(!redacted_json.contains("changed-secret"));
        assert!(redacted.changed[0]
            .before
            .fingerprint
            .starts_with("sha256:"));

        let revealed = diff_storage_states(&before, &after, StateSelection::all(), true);
        assert_eq!(
            revealed.changed[0].before.value,
            Some(json!("local-secret"))
        );
        assert_eq!(
            revealed.changed[0].after.value,
            Some(json!("changed-secret"))
        );
    }

    #[test]
    fn test_state_show_nonexistent_file() {
        let result = state_show("/tmp/nonexistent-agent-browser-state-file.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_state_clear_nonexistent_file() {
        let result = state_clear(Some("/tmp/nonexistent-agent-browser-state-file.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_state_file_matcher_includes_transactional_backups() {
        assert!(is_state_file(std::path::Path::new("auth.json")));
        assert!(is_state_file(std::path::Path::new("auth.json.enc")));
        assert!(is_state_file(std::path::Path::new("auth.json.previous")));
        assert!(is_state_file(std::path::Path::new(
            "auth.json.enc.previous"
        )));
        assert!(is_encrypted_state(std::path::Path::new(
            "auth.json.enc.previous"
        )));
    }

    #[test]
    fn test_state_clear_removes_transactional_backups() {
        let guard = crate::test_utils::EnvGuard::new(&["HOME", "AGENT_BROWSER_NAMESPACE"]);
        let dir = tempfile::tempdir().unwrap();
        guard.set("HOME", dir.path().to_str().unwrap());
        guard.remove("AGENT_BROWSER_NAMESPACE");

        let sessions = get_sessions_dir();
        fs::create_dir_all(&sessions).unwrap();
        fs::write(sessions.join("auth-test.json"), "{}").unwrap();
        fs::write(sessions.join("auth-test.json.previous"), "{}").unwrap();
        fs::write(sessions.join("auth-test.json.enc.previous"), "encrypted").unwrap();

        let result = state_clear(None).unwrap();

        assert_eq!(result["deleted"], 3);
        assert!(!sessions.join("auth-test.json").exists());
        assert!(!sessions.join("auth-test.json.previous").exists());
        assert!(!sessions.join("auth-test.json.enc.previous").exists());
    }

    #[test]
    fn test_state_rename_nonexistent() {
        let result = state_rename("/tmp/nonexistent-agent-browser-state-file.json", "new-name");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_state_list_returns_json() {
        let result = state_list().unwrap();
        assert!(result.get("files").is_some());
        assert!(result.get("directory").is_some());
    }

    #[test]
    fn test_sessions_dir_path() {
        let dir = get_sessions_dir();
        assert!(dir.to_string_lossy().contains("sessions"));
    }

    #[test]
    fn test_get_state_dir_namespace_scopes_sessions() {
        let _guard = crate::test_utils::EnvGuard::new(&["AGENT_BROWSER_NAMESPACE"]);
        _guard.set("AGENT_BROWSER_NAMESPACE", "Worktree: One");

        let dir = get_state_dir();
        let expected_state_suffix = PathBuf::from(".agent-browser")
            .join("namespaces")
            .join("worktree-one")
            .join("state");
        let expected_sessions_suffix = expected_state_suffix.join("sessions");

        assert!(dir.ends_with(expected_state_suffix));
        assert!(get_sessions_dir().ends_with(expected_sessions_suffix));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plain = b"hello world";
        let key = "test-secret-key";
        let encrypted = encrypt_data(plain, key).unwrap();
        assert!(encrypted.len() > 12);
        assert_ne!(&encrypted[12..], plain);
        let decrypted = decrypt_data(&encrypted, key).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let plain = b"secret data";
        let encrypted = encrypt_data(plain, "key1").unwrap();
        let result = decrypt_data(&encrypted, "key2");
        assert!(result.is_err());
    }

    #[test]
    fn test_cookie_serde_roundtrip() {
        let cookie = Cookie {
            name: "test".to_string(),
            value: "123".to_string(),
            domain: ".test.com".to_string(),
            path: "/api".to_string(),
            expires: 1700000000.0,
            size: 7,
            http_only: false,
            secure: true,
            session: false,
            same_site: Some("Strict".to_string()),
            priority: Some("High".to_string()),
            same_party: Some(false),
            source_scheme: Some("Secure".to_string()),
            source_port: Some(443),
            partition_key: Some(json!({ "topLevelSite": "https://test.com" })),
            partition_key_opaque: Some(false),
        };

        let json = serde_json::to_value(&cookie).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["httpOnly"], false);
        assert_eq!(json["secure"], true);
        assert_eq!(json["sameSite"], "Strict");

        let set_value = cookies::to_set_cookie_value(&cookie);
        assert_eq!(set_value["priority"], "High");
        assert_eq!(set_value["sourceScheme"], "Secure");
        assert_eq!(set_value["sourcePort"], 443);
        assert_eq!(
            set_value["partitionKey"]["topLevelSite"],
            "https://test.com"
        );
        assert!(set_value.get("size").is_none());
        assert!(set_value.get("session").is_none());
        assert!(set_value.get("partitionKeyOpaque").is_none());

        let session_cookie = test_cookie("session", "value");
        assert!(cookies::to_set_cookie_value(&session_cookie)
            .get("expires")
            .is_none());
    }

    #[test]
    fn test_dispatch_state_command_routes_state_list() {
        let cmd = serde_json::json!({ "action": "state_list" });
        let result = dispatch_state_command(&cmd);
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_dispatch_state_command_returns_none_for_unknown() {
        let cmd = serde_json::json!({ "action": "navigate" });
        assert!(dispatch_state_command(&cmd).is_none());
    }

    #[test]
    fn test_dispatch_state_command_returns_none_for_missing_action() {
        let cmd = serde_json::json!({});
        assert!(dispatch_state_command(&cmd).is_none());
    }

    #[test]
    fn test_dispatch_state_show_missing_path() {
        let cmd = serde_json::json!({ "action": "state_show" });
        let result = dispatch_state_command(&cmd).unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing 'path' parameter");
    }

    #[test]
    fn test_dispatch_state_rename_missing_params() {
        let cmd = serde_json::json!({ "action": "state_rename" });
        let result = dispatch_state_command(&cmd).unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing 'path' parameter");

        let cmd = serde_json::json!({ "action": "state_rename", "path": "/tmp/test.json" });
        let result = dispatch_state_command(&cmd).unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing 'name' parameter");
    }
}
