use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use url::Url;
use uuid::Uuid;

const EVIDENCE_VERSION: u32 = 1;
const ACTIONS_FILE: &str = "actions.jsonl";
const MANIFEST_FILE: &str = "manifest.json";

pub type EvidenceResult<T> = Result<T, String>;

#[derive(Debug, Clone)]
pub struct EvidenceStartOptions {
    pub output_dir: PathBuf,
    pub metadata: Value,
    pub sensitive_keys: Vec<String>,
    pub include_private: bool,
}

impl EvidenceStartOptions {
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            metadata: Value::Null,
            sensitive_keys: Vec::new(),
            include_private: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActionArtifact {
    pub sequence: u64,
    pub timestamp: String,
    pub action: String,
    pub request: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

macro_rules! timed_artifact {
    ($name:ident) => {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub timestamp: String,
            pub data: Value,
        }

        impl $name {
            pub fn new(data: Value) -> Self {
                Self {
                    timestamp: timestamp(),
                    data,
                }
            }
        }
    };
}

timed_artifact!(DialogArtifact);
timed_artifact!(ConsoleArtifact);
timed_artifact!(ErrorArtifact);
timed_artifact!(NetworkArtifact);
timed_artifact!(FrameArtifact);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceGap {
    pub artifact: String,
    pub reason: String,
}

impl EvidenceGap {
    pub fn new(artifact: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            artifact: artifact.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceScreenshot {
    pub private_path: PathBuf,
    pub redacted_path: Option<PathBuf>,
}

impl EvidenceScreenshot {
    pub fn private(path: impl Into<PathBuf>) -> Self {
        Self {
            private_path: path.into(),
            redacted_path: None,
        }
    }

    pub fn with_redacted(
        private_path: impl Into<PathBuf>,
        redacted_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            private_path: private_path.into(),
            redacted_path: Some(redacted_path.into()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CollectedEvidence {
    pub dialogs: Vec<Value>,
    pub console: Vec<Value>,
    pub errors: Vec<Value>,
    pub network: Vec<Value>,
    pub har: Option<Value>,
    pub interceptions: Vec<Value>,
    pub frames: Vec<Value>,
    pub screenshots: Vec<EvidenceScreenshot>,
    pub gaps: Vec<EvidenceGap>,
}

impl CollectedEvidence {
    pub fn from_values(
        dialogs: Vec<Value>,
        console: Vec<Value>,
        errors: Vec<Value>,
        network: Vec<Value>,
        frames: Vec<Value>,
        screenshot_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            dialogs,
            console,
            errors,
            network,
            har: None,
            interceptions: Vec::new(),
            frames,
            screenshots: screenshot_paths
                .into_iter()
                .map(EvidenceScreenshot::private)
                .collect(),
            gaps: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactVisibility {
    Private,
    Redacted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManifestArtifact {
    pub kind: String,
    pub visibility: ArtifactVisibility,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceManifest {
    pub version: u32,
    pub bundle_id: String,
    pub started_at: String,
    pub stopped_at: String,
    pub complete: bool,
    pub private_artifacts: bool,
    pub metadata: Value,
    pub counts: BTreeMap<String, u64>,
    pub artifacts: Vec<ManifestArtifact>,
    pub gaps: Vec<EvidenceGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceStatus {
    pub active: bool,
    pub bundle_id: String,
    pub output_dir: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    pub private_artifacts: bool,
    pub counts: BTreeMap<String, u64>,
    pub gaps: Vec<EvidenceGap>,
}

#[derive(Debug, Clone)]
struct PendingArtifact {
    kind: String,
    visibility: ArtifactVisibility,
    path: PathBuf,
    records: u64,
}

#[derive(Debug)]
pub struct EvidenceState {
    root: PathBuf,
    private_dir: Option<PathBuf>,
    redacted_dir: PathBuf,
    bundle_id: String,
    started_at: String,
    stopped_at: Option<String>,
    metadata: Value,
    redactor: SecretRedactor,
    counts: BTreeMap<String, u64>,
    gaps: Vec<EvidenceGap>,
    artifacts: Vec<PendingArtifact>,
}

impl EvidenceState {
    pub fn start(options: EvidenceStartOptions) -> EvidenceResult<Self> {
        prepare_bundle_dir(&options.output_dir)?;
        let private_dir = options.output_dir.join("private");
        let redacted_dir = options.output_dir.join("redacted");
        if options.include_private {
            create_secure_dir(&private_dir)?;
        }
        create_secure_dir(&redacted_dir)?;

        let private_actions = private_dir.join(ACTIONS_FILE);
        let redacted_actions = redacted_dir.join(ACTIONS_FILE);
        if options.include_private {
            create_secure_file(&private_actions)?;
        }
        create_secure_file(&redacted_actions)?;

        let mut counts = BTreeMap::new();
        for kind in [
            "actions",
            "dialogs",
            "console",
            "errors",
            "network",
            "har",
            "interceptions",
            "frames",
            "screenshots",
        ] {
            counts.insert(kind.to_string(), 0);
        }

        let mut artifacts = Vec::new();
        if options.include_private {
            artifacts.push(PendingArtifact {
                kind: "actions".to_string(),
                visibility: ArtifactVisibility::Private,
                path: private_actions,
                records: 0,
            });
        }
        artifacts.push(PendingArtifact {
            kind: "actions".to_string(),
            visibility: ArtifactVisibility::Redacted,
            path: redacted_actions,
            records: 0,
        });

        Ok(Self {
            root: options.output_dir,
            private_dir: options.include_private.then_some(private_dir),
            redacted_dir,
            bundle_id: Uuid::new_v4().to_string(),
            started_at: timestamp(),
            stopped_at: None,
            metadata: options.metadata,
            redactor: SecretRedactor::new(options.sensitive_keys),
            counts,
            gaps: Vec::new(),
            artifacts,
        })
    }

    pub fn output_dir(&self) -> &Path {
        &self.root
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn redactor(&self) -> &SecretRedactor {
        &self.redactor
    }

    pub fn includes_private(&self) -> bool {
        self.private_dir.is_some()
    }

    pub fn status(&self) -> EvidenceStatus {
        EvidenceStatus {
            active: self.stopped_at.is_none(),
            bundle_id: self.bundle_id.clone(),
            output_dir: self.root.display().to_string(),
            started_at: self.started_at.clone(),
            stopped_at: self.stopped_at.clone(),
            private_artifacts: self.private_dir.is_some(),
            counts: self.counts.clone(),
            gaps: self.gaps.clone(),
        }
    }

    pub fn add_gap(&mut self, gap: EvidenceGap) -> EvidenceResult<()> {
        self.ensure_active()?;
        if !self.gaps.contains(&gap) {
            self.gaps.push(gap);
        }
        Ok(())
    }

    pub fn record_action(
        &mut self,
        action: impl Into<String>,
        request: Value,
        response: Option<Value>,
        error: Option<String>,
        duration_ms: Option<u64>,
    ) -> EvidenceResult<ActionArtifact> {
        self.ensure_active()?;
        let record = ActionArtifact {
            sequence: self.count("actions") + 1,
            timestamp: timestamp(),
            action: action.into(),
            request,
            response,
            error,
            duration_ms,
        };
        self.record_action_artifact(&record)?;
        Ok(record)
    }

    pub fn record_action_artifact(&mut self, record: &ActionArtifact) -> EvidenceResult<()> {
        self.ensure_active()?;
        let raw = serde_json::to_value(record)
            .map_err(|e| format!("Failed to serialize evidence action: {}", e))?;
        let mut redacted = self.redactor.redact_json(&raw);
        redact_action_inputs(&self.redactor, &mut redacted);
        if let Some(private_dir) = &self.private_dir {
            append_jsonl(&private_dir.join(ACTIONS_FILE), &raw)?;
        }
        append_jsonl(&self.redacted_dir.join(ACTIONS_FILE), &redacted)?;
        self.increment("actions", 1);
        for artifact in &mut self.artifacts {
            if artifact.kind == "actions" {
                artifact.records = self.counts["actions"];
            }
        }
        Ok(())
    }

    pub fn stop(&mut self, collected: CollectedEvidence) -> EvidenceResult<EvidenceManifest> {
        self.finalize(collected)
    }

    pub fn finalize(&mut self, collected: CollectedEvidence) -> EvidenceResult<EvidenceManifest> {
        self.ensure_active()?;

        self.write_collection("dialogs", "dialogs.json", &collected.dialogs)?;
        self.write_collection("console", "console.json", &collected.console)?;
        self.write_collection("errors", "errors.json", &collected.errors)?;
        self.write_collection("network", "network.json", &collected.network)?;
        if let Some(har) = &collected.har {
            let records = har
                .pointer("/log/entries")
                .and_then(Value::as_array)
                .map(|entries| entries.len() as u64)
                .unwrap_or(0);
            self.write_value("har", "network.har", har, records)?;
        }
        self.write_collection(
            "interceptions",
            "interceptions.json",
            &collected.interceptions,
        )?;
        self.write_collection("frames", "frames.json", &collected.frames)?;
        self.import_screenshots(&collected.screenshots)?;
        self.gaps.extend(collected.gaps);

        let stopped_at = timestamp();
        let artifacts = self.hash_artifacts()?;
        let manifest = EvidenceManifest {
            version: EVIDENCE_VERSION,
            bundle_id: self.bundle_id.clone(),
            started_at: self.started_at.clone(),
            stopped_at: stopped_at.clone(),
            complete: self.gaps.is_empty(),
            private_artifacts: self.private_dir.is_some(),
            metadata: self.redactor.redact_json(&self.metadata),
            counts: self.counts.clone(),
            artifacts,
            gaps: self.gaps.clone(),
        };
        write_json_file(&self.root.join(MANIFEST_FILE), &manifest)?;
        self.stopped_at = Some(stopped_at);
        Ok(manifest)
    }

    fn write_collection(
        &mut self,
        kind: &str,
        filename: &str,
        values: &[Value],
    ) -> EvidenceResult<()> {
        validate_artifact_filename(filename)?;
        let raw = Value::Array(values.to_vec());
        let redacted = self.redactor.redact_json(&raw);
        let redacted_path = self.redacted_dir.join(filename);
        if let Some(private_dir) = &self.private_dir {
            let private_path = private_dir.join(filename);
            write_json_file(&private_path, &raw)?;
            self.artifacts.push(PendingArtifact {
                kind: kind.to_string(),
                visibility: ArtifactVisibility::Private,
                path: private_path,
                records: values.len() as u64,
            });
        }
        write_json_file(&redacted_path, &redacted)?;
        let records = values.len() as u64;
        self.counts.insert(kind.to_string(), records);
        self.artifacts.push(PendingArtifact {
            kind: kind.to_string(),
            visibility: ArtifactVisibility::Redacted,
            path: redacted_path,
            records,
        });
        Ok(())
    }

    fn write_value(
        &mut self,
        kind: &str,
        filename: &str,
        raw: &Value,
        records: u64,
    ) -> EvidenceResult<()> {
        validate_artifact_filename(filename)?;
        let redacted = self.redactor.redact_json(raw);
        if let Some(private_dir) = &self.private_dir {
            let private_path = private_dir.join(filename);
            write_json_file(&private_path, raw)?;
            self.artifacts.push(PendingArtifact {
                kind: kind.to_string(),
                visibility: ArtifactVisibility::Private,
                path: private_path,
                records,
            });
        }
        let redacted_path = self.redacted_dir.join(filename);
        write_json_file(&redacted_path, &redacted)?;
        self.artifacts.push(PendingArtifact {
            kind: kind.to_string(),
            visibility: ArtifactVisibility::Redacted,
            path: redacted_path,
            records,
        });
        self.counts.insert(kind.to_string(), records);
        Ok(())
    }

    fn import_screenshots(&mut self, screenshots: &[EvidenceScreenshot]) -> EvidenceResult<()> {
        let private_screenshots = self
            .private_dir
            .as_ref()
            .map(|path| path.join("screenshots"));
        let redacted_screenshots = self.redacted_dir.join("screenshots");
        if !screenshots.is_empty() {
            if let Some(private_screenshots) = &private_screenshots {
                create_secure_dir(private_screenshots)?;
            }
            create_secure_dir(&redacted_screenshots)?;
        }

        for (index, screenshot) in screenshots.iter().enumerate() {
            let extension = safe_extension(&screenshot.private_path);
            let filename = format!("{:04}.{}", index + 1, extension);
            if let Some(private_screenshots) = &private_screenshots {
                let private_destination = private_screenshots.join(&filename);
                copy_secure_file(&screenshot.private_path, &private_destination)?;
                self.artifacts.push(PendingArtifact {
                    kind: "screenshots".to_string(),
                    visibility: ArtifactVisibility::Private,
                    path: private_destination,
                    records: 1,
                });
            }

            if let Some(redacted_source) = &screenshot.redacted_path {
                let redacted_extension = safe_extension(redacted_source);
                let redacted_filename = format!("{:04}.{}", index + 1, redacted_extension);
                let redacted_destination = redacted_screenshots.join(redacted_filename);
                copy_secure_file(redacted_source, &redacted_destination)?;
                self.artifacts.push(PendingArtifact {
                    kind: "screenshots".to_string(),
                    visibility: ArtifactVisibility::Redacted,
                    path: redacted_destination,
                    records: 1,
                });
            } else {
                self.gaps.push(EvidenceGap::new(
                    format!("redacted/screenshots/{}", filename),
                    "Screenshot omitted because no pixel-redacted source was supplied",
                ));
            }
        }
        self.counts
            .insert("screenshots".to_string(), screenshots.len() as u64);
        Ok(())
    }

    fn hash_artifacts(&self) -> EvidenceResult<Vec<ManifestArtifact>> {
        let mut artifacts = Vec::with_capacity(self.artifacts.len());
        for pending in &self.artifacts {
            let (sha256, bytes) = hash_file(&pending.path)?;
            let relative = pending.path.strip_prefix(&self.root).map_err(|_| {
                format!(
                    "Evidence artifact escaped bundle directory: {}",
                    pending.path.display()
                )
            })?;
            artifacts.push(ManifestArtifact {
                kind: pending.kind.clone(),
                visibility: pending.visibility,
                path: path_for_manifest(relative),
                sha256,
                bytes,
                records: pending.records,
            });
        }
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(artifacts)
    }

    fn ensure_active(&self) -> EvidenceResult<()> {
        if self.stopped_at.is_some() {
            Err("Evidence bundle has already been finalized".to_string())
        } else {
            Ok(())
        }
    }

    fn count(&self, kind: &str) -> u64 {
        self.counts.get(kind).copied().unwrap_or(0)
    }

    fn increment(&mut self, kind: &str, amount: u64) {
        *self.counts.entry(kind.to_string()).or_insert(0) += amount;
    }
}

pub fn evidence_start(options: EvidenceStartOptions) -> EvidenceResult<EvidenceState> {
    EvidenceState::start(options)
}

pub fn evidence_status(state: &EvidenceState) -> EvidenceStatus {
    state.status()
}

pub fn evidence_action(
    state: &mut EvidenceState,
    action: impl Into<String>,
    request: Value,
    response: Option<Value>,
    error: Option<String>,
    duration_ms: Option<u64>,
) -> EvidenceResult<ActionArtifact> {
    state.record_action(action, request, response, error, duration_ms)
}

pub fn evidence_stop(
    state: &mut EvidenceState,
    collected: CollectedEvidence,
) -> EvidenceResult<EvidenceManifest> {
    state.stop(collected)
}

#[derive(Debug, Clone)]
pub struct SecretRedactor {
    sensitive_keys: BTreeSet<String>,
}

impl Default for SecretRedactor {
    fn default() -> Self {
        Self::new(std::iter::empty::<String>())
    }
}

impl SecretRedactor {
    pub fn new(additional_sensitive_keys: impl IntoIterator<Item = String>) -> Self {
        let mut sensitive_keys = BTreeSet::new();
        for key in [
            "access_token",
            "api_key",
            "apikey",
            "authorization",
            "auth_token",
            "body",
            "client_secret",
            "code_verifier",
            "command_line",
            "cookie",
            "credentials",
            "csrf_token",
            "id_token",
            "jwt",
            "password",
            "passwd",
            "passphrase",
            "private_key",
            "post_data",
            "proxy_authorization",
            "refresh_token",
            "request_body",
            "response_body",
            "secret",
            "session",
            "session_id",
            "set_cookie",
            "token",
            "x_api_key",
            "x_auth_token",
            "xsrf_token",
        ] {
            sensitive_keys.insert(normalize_key(key));
        }
        sensitive_keys.extend(
            additional_sensitive_keys
                .into_iter()
                .map(|key| normalize_key(&key))
                .filter(|key| !key.is_empty()),
        );
        Self { sensitive_keys }
    }

    pub fn for_terminal() -> Self {
        let mut redactor = Self::default();
        for key in ["session", "session_id"] {
            redactor.sensitive_keys.remove(&normalize_key(key));
        }
        redactor
    }

    pub fn placeholder(&self, secret: &str) -> String {
        if is_placeholder(secret) {
            return secret.to_string();
        }
        let digest = Sha256::digest(secret.as_bytes());
        format!("<redacted:sha256:{}>", hex::encode(digest))
    }

    pub fn redact_json(&self, value: &Value) -> Value {
        let mut redacted = self.redact_value(value, None);
        redact_har_payloads(self, &mut redacted);
        redacted
    }

    pub fn redact_json_text(&self, value: &str) -> EvidenceResult<String> {
        let parsed: Value = serde_json::from_str(value)
            .map_err(|e| format!("Failed to parse JSON for redaction: {}", e))?;
        serde_json::to_string(&self.redact_json(&parsed))
            .map_err(|e| format!("Failed to serialize redacted JSON: {}", e))
    }

    pub fn redact_url(&self, value: &str) -> String {
        if let Ok(mut url) = Url::parse(value) {
            if !url.username().is_empty() {
                let username = self.placeholder(url.username());
                let _ = url.set_username(&username);
            }
            if let Some(password) = url.password() {
                let password = self.placeholder(password);
                let _ = url.set_password(Some(&password));
            }
            if let Some(query) = url.query() {
                let redacted = self.redact_form_encoded(query);
                url.set_query(Some(&redacted));
            }
            if let Some(fragment) = url.fragment() {
                if let Some((route, query)) = fragment.split_once('?') {
                    let redacted = format!("{}?{}", route, self.redact_form_encoded(query));
                    url.set_fragment(Some(&redacted));
                } else if looks_like_form(fragment) {
                    let redacted = self.redact_form_encoded(fragment);
                    url.set_fragment(Some(&redacted));
                }
            }
            return url.to_string();
        }

        redact_relative_url(self, value)
    }

    pub fn redact_headers(&self, headers: &Value) -> Value {
        match headers {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(name, value)| (name.clone(), self.redact_header_value(name, value)))
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| {
                        if let Value::Object(header) = value {
                            let name = header
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            let mut redacted = header.clone();
                            if let Some(header_value) = header.get("value") {
                                redacted.insert(
                                    "value".to_string(),
                                    self.redact_header_value(name, header_value),
                                );
                            }
                            Value::Object(redacted)
                        } else {
                            self.redact_json(value)
                        }
                    })
                    .collect(),
            ),
            _ => self.redact_json(headers),
        }
    }

    pub fn redact_cookies(&self, cookies: &Value) -> Value {
        match cookies {
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| match value {
                        Value::Object(cookie) => {
                            let mut redacted = cookie.clone();
                            if let Some(cookie_value) = cookie.get("value") {
                                redacted.insert(
                                    "value".to_string(),
                                    self.redact_secret_value(cookie_value),
                                );
                            }
                            Value::Object(redacted)
                        }
                        _ => self.redact_secret_value(value),
                    })
                    .collect(),
            ),
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(name, value)| (name.clone(), self.redact_secret_value(value)))
                    .collect(),
            ),
            Value::String(value) => Value::String(self.redact_cookie_header(value, false)),
            _ => self.redact_secret_value(cookies),
        }
    }

    pub fn redact_form(&self, form: &Value) -> Value {
        match form {
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(name, value)| {
                        let redacted = if self.is_sensitive_key(name) {
                            self.redact_secret_value(value)
                        } else {
                            self.redact_value(value, Some(name))
                        };
                        (name.clone(), redacted)
                    })
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| {
                        if let Value::Object(field) = value {
                            let name = field
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            let mut redacted = field.clone();
                            if self.is_sensitive_key(name) {
                                if let Some(field_value) = field.get("value") {
                                    redacted.insert(
                                        "value".to_string(),
                                        self.redact_secret_value(field_value),
                                    );
                                }
                            } else if let Some(field_value) = field.get("value") {
                                redacted.insert(
                                    "value".to_string(),
                                    self.redact_value(field_value, Some(name)),
                                );
                            }
                            Value::Object(redacted)
                        } else {
                            self.redact_form(value)
                        }
                    })
                    .collect(),
            ),
            Value::String(value) => Value::String(self.redact_form_encoded(value)),
            _ => form.clone(),
        }
    }

    pub fn redact_form_encoded(&self, form: &str) -> String {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(form.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in pairs {
            if self.is_sensitive_key(&name) {
                serializer.append_pair(&name, &self.placeholder(&value));
            } else if is_url_key(&name) {
                serializer.append_pair(&name, &self.redact_url(&value));
            } else {
                serializer.append_pair(&name, &value);
            }
        }
        serializer.finish()
    }

    fn redact_value(&self, value: &Value, field_name: Option<&str>) -> Value {
        if let Some(field_name) = field_name {
            if self.is_sensitive_key(field_name) {
                return self.redact_secret_value(value);
            }
            if is_url_key(field_name) {
                if let Value::String(url) = value {
                    return Value::String(self.redact_url(url));
                }
            }
            if is_headers_key(field_name) {
                return self.redact_headers(value);
            }
            if is_cookies_key(field_name) {
                return self.redact_cookies(value);
            }
            if is_form_key(field_name) {
                return self.redact_form(value);
            }
            if is_body_key(field_name) {
                if let Value::String(body) = value {
                    return Value::String(self.redact_body(body));
                }
            }
        }

        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(name, value)| (name.clone(), self.redact_value(value, Some(name))))
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| self.redact_value(value, field_name))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    fn redact_header_value(&self, name: &str, value: &Value) -> Value {
        let normalized = normalize_key(name);
        if normalized == "cookie" {
            return match value {
                Value::String(value) => Value::String(self.redact_cookie_header(value, false)),
                _ => self.redact_cookies(value),
            };
        }
        if normalized == "setcookie" {
            return match value {
                Value::String(value) => Value::String(self.redact_cookie_header(value, true)),
                Value::Array(values) => Value::Array(
                    values
                        .iter()
                        .map(|value| match value {
                            Value::String(value) => {
                                Value::String(self.redact_cookie_header(value, true))
                            }
                            _ => self.redact_secret_value(value),
                        })
                        .collect(),
                ),
                _ => self.redact_secret_value(value),
            };
        }
        if self.is_sensitive_key(name) || is_authorization_header(&normalized) {
            return self.redact_secret_value(value);
        }
        self.redact_value(value, Some(name))
    }

    fn redact_cookie_header(&self, header: &str, set_cookie: bool) -> String {
        let mut parts = header.split(';');
        let first = parts.next().unwrap_or_default();
        let redact_part = |part: &str| {
            let (prefix, content) = split_leading_whitespace(part);
            if let Some((name, value)) = content.split_once('=') {
                format!("{}{}={}", prefix, name, self.placeholder(value))
            } else {
                format!("{}{}", prefix, self.placeholder(content))
            }
        };

        if set_cookie {
            let mut result = redact_part(first);
            for part in parts {
                result.push(';');
                result.push_str(part);
            }
            result
        } else {
            std::iter::once(first)
                .chain(parts)
                .map(redact_part)
                .collect::<Vec<_>>()
                .join(";")
        }
    }

    fn redact_body(&self, body: &str) -> String {
        let trimmed = body.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
                return serde_json::to_string(&self.redact_json(&value))
                    .unwrap_or_else(|_| self.placeholder(body));
            }
        }
        if looks_like_form(trimmed) {
            return self.redact_form_encoded(body);
        }
        body.to_string()
    }

    fn redact_secret_value(&self, value: &Value) -> Value {
        if value.is_null() {
            return Value::Null;
        }
        let secret = match value {
            Value::String(value) => value.clone(),
            _ => serde_json::to_string(value).unwrap_or_default(),
        };
        Value::String(self.placeholder(&secret))
    }

    fn is_sensitive_key(&self, key: &str) -> bool {
        let key = normalize_key(key);
        self.sensitive_keys.contains(&key)
            || [
                "password",
                "passwd",
                "passphrase",
                "secret",
                "token",
                "apikey",
                "authkey",
                "privatekey",
                "clientsecret",
                "credential",
                "credentials",
                "sessionid",
                "codeverifier",
            ]
            .iter()
            .any(|suffix| key.ends_with(suffix))
    }
}

fn redact_action_inputs(redactor: &SecretRedactor, record: &mut Value) {
    let action = record
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(request) = record.get_mut("request").and_then(Value::as_object_mut) else {
        return;
    };
    let fields: &[&str] = match action.as_str() {
        "evaluate" | "addscript" | "addinitscript" => &["script"],
        "fill" | "type" | "setvalue" | "inserttext" | "input_keyboard" => &["text", "value"],
        "dialog" => &["promptText"],
        "postmessage_send" => &["data"],
        _ => &[],
    };
    for field in fields {
        if let Some(value) = request.get_mut(*field) {
            let serialized = match &*value {
                Value::String(value) => value.clone(),
                value => value.to_string(),
            };
            *value = Value::String(redactor.placeholder(&serialized));
        }
    }
}

fn redact_har_payloads(redactor: &SecretRedactor, value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                redact_har_payloads(redactor, value);
            }
        }
        Value::Object(object) => {
            if let Some(query) = object.get_mut("queryString").and_then(Value::as_array_mut) {
                for pair in query {
                    let secret = pair
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| redactor.is_sensitive_key(name));
                    if secret {
                        if let Some(raw) = pair.get_mut("value") {
                            let text = raw.as_str().unwrap_or_default().to_string();
                            *raw = Value::String(redactor.placeholder(&text));
                        }
                    }
                }
            }
            if let Some(post_data) = object.get_mut("postData").and_then(Value::as_object_mut) {
                redact_body_text(redactor, post_data);
            }
            if let Some(content) = object.get_mut("content").and_then(Value::as_object_mut) {
                redact_body_text(redactor, content);
            }
            for child in object.values_mut() {
                redact_har_payloads(redactor, child);
            }
        }
        _ => {}
    }
}

fn redact_body_text(redactor: &SecretRedactor, body: &mut serde_json::Map<String, Value>) {
    let Some(raw) = body.remove("text") else {
        return;
    };
    let text = raw.as_str().unwrap_or_default();
    let digest = redactor.placeholder(text);
    body.insert("textDigest".to_string(), Value::String(digest));
    body.insert("textOmitted".to_string(), Value::Bool(true));
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_placeholder(value: &str) -> bool {
    value.starts_with("<redacted:sha256:") && value.ends_with('>')
}

fn is_url_key(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "url" | "uri" | "href" | "location" | "documenturl" | "requesturl"
    )
}

fn is_headers_key(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "headers" | "requestheaders" | "responseheaders"
    )
}

fn is_cookies_key(key: &str) -> bool {
    matches!(normalize_key(key).as_str(), "cookies" | "setcookies")
}

fn is_form_key(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "form" | "formdata" | "formfields" | "fields"
    )
}

fn is_body_key(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "body" | "postdata" | "requestbody" | "responsebody"
    )
}

fn is_authorization_header(normalized: &str) -> bool {
    matches!(
        normalized,
        "authorization"
            | "proxyauthorization"
            | "xapikey"
            | "xauthtoken"
            | "xaccesskey"
            | "xsecretkey"
    )
}

fn looks_like_form(value: &str) -> bool {
    value.split('&').any(|part| {
        part.split_once('=')
            .map(|(name, _)| !name.is_empty())
            .unwrap_or(false)
    })
}

fn redact_relative_url(redactor: &SecretRedactor, value: &str) -> String {
    let (without_fragment, fragment) = value
        .split_once('#')
        .map_or((value, None), |(base, fragment)| (base, Some(fragment)));
    let (path, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, None), |(path, query)| {
            (path, Some(query))
        });

    let mut result = path.to_string();
    if let Some(query) = query {
        result.push('?');
        result.push_str(&redactor.redact_form_encoded(query));
    }
    if let Some(fragment) = fragment {
        result.push('#');
        if let Some((route, query)) = fragment.split_once('?') {
            result.push_str(route);
            result.push('?');
            result.push_str(&redactor.redact_form_encoded(query));
        } else if looks_like_form(fragment) {
            result.push_str(&redactor.redact_form_encoded(fragment));
        } else {
            result.push_str(fragment);
        }
    }
    result
}

fn split_leading_whitespace(value: &str) -> (&str, &str) {
    let index = value
        .find(|character: char| !character.is_ascii_whitespace())
        .unwrap_or(value.len());
    value.split_at(index)
}

fn prepare_bundle_dir(path: &Path) -> EvidenceResult<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|e| {
            format!(
                "Failed to inspect evidence bundle directory {}: {}",
                path.display(),
                e
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "Evidence output must be a directory, not a symlink or file: {}",
                path.display()
            ));
        }
        let mut entries = fs::read_dir(path).map_err(|e| {
            format!(
                "Failed to inspect evidence bundle directory {}: {}",
                path.display(),
                e
            )
        })?;
        if entries.next().is_some() {
            return Err(format!(
                "Evidence output directory is not empty: {}",
                path.display()
            ));
        }
    }
    create_secure_dir(path)
}

fn create_secure_dir(path: &Path) -> EvidenceResult<()> {
    fs::create_dir_all(path)
        .map_err(|e| format!("Failed to create directory {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
            format!(
                "Failed to secure directory permissions for {}: {}",
                path.display(),
                e
            )
        })?;
    }
    Ok(())
}

fn create_secure_file(path: &Path) -> EvidenceResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("Failed to create evidence file {}: {}", path.display(), e))?;
    set_file_private(path)?;
    Ok(file)
}

fn open_secure_append(path: &Path) -> EvidenceResult<File> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("Failed to inspect evidence file {}: {}", path.display(), e))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "Evidence artifact is not a regular file: {}",
            path.display()
        ));
    }
    set_file_private(path)?;
    OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| format!("Failed to append evidence file {}: {}", path.display(), e))
}

fn set_file_private(path: &Path) -> EvidenceResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            format!(
                "Failed to secure file permissions for {}: {}",
                path.display(),
                e
            )
        })?;
    }
    Ok(())
}

fn append_jsonl(path: &Path, value: &Value) -> EvidenceResult<()> {
    let mut file = open_secure_append(path)?;
    serde_json::to_writer(&mut file, value).map_err(|e| {
        format!(
            "Failed to serialize evidence JSONL {}: {}",
            path.display(),
            e
        )
    })?;
    file.write_all(b"\n")
        .map_err(|e| format!("Failed to append evidence JSONL {}: {}", path.display(), e))?;
    file.sync_data()
        .map_err(|e| format!("Failed to flush evidence JSONL {}: {}", path.display(), e))
}

fn write_json_file(path: &Path, value: &impl Serialize) -> EvidenceResult<()> {
    let mut file = create_secure_file(path)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|e| {
        format!(
            "Failed to serialize evidence file {}: {}",
            path.display(),
            e
        )
    })?;
    file.write_all(b"\n")
        .map_err(|e| format!("Failed to write evidence file {}: {}", path.display(), e))?;
    file.sync_all()
        .map_err(|e| format!("Failed to flush evidence file {}: {}", path.display(), e))
}

fn copy_secure_file(source: &Path, destination: &Path) -> EvidenceResult<()> {
    let source_metadata = fs::symlink_metadata(source).map_err(|e| {
        format!(
            "Failed to inspect screenshot source {}: {}",
            source.display(),
            e
        )
    })?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(format!(
            "Screenshot source is not a regular file: {}",
            source.display()
        ));
    }
    let mut input = File::open(source)
        .map_err(|e| format!("Failed to open screenshot {}: {}", source.display(), e))?;
    let mut output = create_secure_file(destination)?;
    std::io::copy(&mut input, &mut output).map_err(|e| {
        format!(
            "Failed to copy screenshot {} to {}: {}",
            source.display(),
            destination.display(),
            e
        )
    })?;
    output.sync_all().map_err(|e| {
        format!(
            "Failed to flush screenshot {}: {}",
            destination.display(),
            e
        )
    })?;
    Ok(())
}

fn validate_artifact_filename(filename: &str) -> EvidenceResult<()> {
    let path = Path::new(filename);
    let mut components = path.components();
    let valid_component = matches!(components.next(), Some(Component::Normal(_)));
    let only_component = components.next().is_none();
    let valid_chars = filename
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character));
    if valid_component && only_component && valid_chars {
        Ok(())
    } else {
        Err(format!("Invalid evidence artifact filename: {}", filename))
    }
}

fn safe_extension(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .filter(|extension| {
            !extension.is_empty()
                && extension.len() <= 10
                && extension
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
        .unwrap_or_else(|| "bin".to_string())
}

fn hash_file(path: &Path) -> EvidenceResult<(String, u64)> {
    let mut file = File::open(path).map_err(|e| {
        format!(
            "Failed to open artifact for hashing {}: {}",
            path.display(),
            e
        )
    })?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed to hash artifact {}: {}", path.display(), e))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn path_for_manifest(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn placeholders_are_deterministic_distinct_and_idempotent() {
        let redactor = SecretRedactor::default();
        let first = redactor.placeholder("high-value-secret");
        let again = redactor.placeholder("high-value-secret");
        let other = redactor.placeholder("another-secret");

        assert_eq!(first, again);
        assert_ne!(first, other);
        assert!(!first.contains("high-value-secret"));
        assert_eq!(redactor.placeholder(&first), first);
        assert_eq!(first.len(), "<redacted:sha256:>".len() + 64);
    }

    #[test]
    fn redacts_nested_json_urls_headers_cookies_and_bodies() {
        let redactor = SecretRedactor::new(["tenant-pin".to_string()]);
        let value = json!({
            "url": "https://alice:pw@example.test/path?q=public&access_token=url-secret#refresh_token=fragment-secret",
            "headers": {
                "Authorization": "Bearer header-secret",
                "Cookie": "sid=cookie-secret; theme=dark",
                "X-Trace": "public-trace"
            },
            "cookies": [{"name": "sid", "value": "structured-cookie", "domain": "example.test"}],
            "formData": {"username": "alice", "password": "form-secret", "tenant-pin": 1234},
            "fields": [{"name": "password", "value": "array-form-secret"}, {"name": "safe", "value": "kept"}],
            "requestBody": "{\"refresh_token\":\"json-body-secret\",\"safe\":\"kept\"}",
            "responseBody": "safe=yes&api_key=form-body-secret",
            "nested": {"clientSecret": "nested-secret", "safe": "visible"}
        });

        let redacted = redactor.redact_json(&value);
        let text = serde_json::to_string(&redacted).unwrap();
        for secret in [
            "pw",
            "url-secret",
            "fragment-secret",
            "header-secret",
            "cookie-secret",
            "structured-cookie",
            "form-secret",
            "array-form-secret",
            "json-body-secret",
            "form-body-secret",
            "nested-secret",
        ] {
            assert!(!text.contains(secret), "secret leaked: {}", secret);
        }
        assert_eq!(redacted["headers"]["X-Trace"], "public-trace");
        assert_eq!(redacted["formData"]["username"], "alice");
        assert_eq!(redacted["fields"][1]["value"], "kept");
        assert_eq!(redacted["nested"]["safe"], "visible");
        assert!(redacted["formData"]["tenant-pin"]
            .as_str()
            .unwrap()
            .starts_with("<redacted:sha256:"));

        let url = Url::parse(redacted["url"].as_str().unwrap()).unwrap();
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["q"], "public");
        assert!(query["access_token"].starts_with("<redacted:sha256:"));
        assert!(url.fragment().unwrap().contains("%3Credacted%3Asha256%3A"));
    }

    #[test]
    fn cookie_and_set_cookie_redaction_preserves_names_and_attributes() {
        let redactor = SecretRedactor::default();
        let headers = json!({
            "Cookie": "session=abc; preference=blue",
            "Set-Cookie": "session=def; Path=/; Secure; HttpOnly"
        });
        let redacted = redactor.redact_headers(&headers);
        let cookie = redacted["Cookie"].as_str().unwrap();
        let set_cookie = redacted["Set-Cookie"].as_str().unwrap();

        assert!(cookie.contains("session=<redacted:sha256:"));
        assert!(cookie.contains("preference=<redacted:sha256:"));
        assert!(!cookie.contains("abc"));
        assert!(set_cookie.contains("session=<redacted:sha256:"));
        assert!(set_cookie.ends_with("; Path=/; Secure; HttpOnly"));
        assert!(!set_cookie.contains("def"));
    }

    #[test]
    fn evidence_bundle_separates_raw_and_redacted_artifacts() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("bundle");
        let screenshot = temporary.path().join("capture.png");
        fs::write(&screenshot, b"private screenshot bytes").unwrap();

        let mut options = EvidenceStartOptions::new(&output);
        options.include_private = true;
        options.metadata = json!({"authorization": "metadata-secret", "target": "example.test"});
        let mut state = EvidenceState::start(options).unwrap();
        let action = state
            .record_action(
                "navigate",
                json!({"url": "https://example.test/?token=action-secret"}),
                Some(json!({"ok": true})),
                None,
                Some(12),
            )
            .unwrap();
        assert_eq!(action.sequence, 1);

        let collected = CollectedEvidence::from_values(
            vec![json!({"message": "proof", "password": "dialog-secret"})],
            vec![json!({"text": "safe console"})],
            vec![],
            vec![json!({
                "url": "https://example.test/api?api_key=network-secret",
                "requestHeaders": {"Authorization": "Bearer request-secret"}
            })],
            vec![],
            vec![screenshot],
        );
        let manifest = state.stop(collected).unwrap();

        assert!(!manifest.complete);
        assert_eq!(manifest.counts["actions"], 1);
        assert_eq!(manifest.counts["dialogs"], 1);
        assert_eq!(manifest.counts["network"], 1);
        assert_eq!(manifest.counts["screenshots"], 1);
        assert_eq!(manifest.gaps.len(), 1);
        assert!(manifest.gaps[0]
            .artifact
            .starts_with("redacted/screenshots/"));

        let private_actions = fs::read_to_string(output.join("private/actions.jsonl")).unwrap();
        let redacted_actions = fs::read_to_string(output.join("redacted/actions.jsonl")).unwrap();
        assert!(private_actions.contains("action-secret"));
        assert!(!redacted_actions.contains("action-secret"));
        assert!(redacted_actions.contains("redacted%3Asha256%3A"));

        let private_dialogs = fs::read_to_string(output.join("private/dialogs.json")).unwrap();
        let redacted_dialogs = fs::read_to_string(output.join("redacted/dialogs.json")).unwrap();
        assert!(private_dialogs.contains("dialog-secret"));
        assert!(!redacted_dialogs.contains("dialog-secret"));
        assert!(output.join("private/screenshots/0001.png").exists());
        assert!(!output.join("redacted/screenshots/0001.png").exists());

        for artifact in &manifest.artifacts {
            let path = output.join(&artifact.path);
            let (digest, bytes) = hash_file(&path).unwrap();
            assert_eq!(artifact.sha256, digest);
            assert_eq!(artifact.bytes, bytes);
        }
        assert!(!fs::read_to_string(output.join("manifest.json"))
            .unwrap()
            .contains("metadata-secret"));
        assert!(!state.status().active);
        assert!(state
            .record_action("late", json!({}), None, None, None)
            .is_err());
    }

    #[test]
    fn supplied_redacted_screenshot_keeps_bundle_complete() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("bundle");
        let raw = temporary.path().join("raw.png");
        let redacted = temporary.path().join("redacted.png");
        fs::write(&raw, b"raw pixels").unwrap();
        fs::write(&redacted, b"redacted pixels").unwrap();

        let mut options = EvidenceStartOptions::new(&output);
        options.include_private = true;
        let mut state = EvidenceState::start(options).unwrap();
        let manifest = state
            .finalize(CollectedEvidence {
                screenshots: vec![EvidenceScreenshot::with_redacted(raw, redacted)],
                ..CollectedEvidence::default()
            })
            .unwrap();

        assert!(manifest.complete);
        assert!(manifest.gaps.is_empty());
        assert_eq!(
            fs::read(output.join("private/screenshots/0001.png")).unwrap(),
            b"raw pixels"
        );
        assert_eq!(
            fs::read(output.join("redacted/screenshots/0001.png")).unwrap(),
            b"redacted pixels"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bundle_directories_and_files_have_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("bundle");
        let mut options = EvidenceStartOptions::new(&output);
        options.include_private = true;
        let mut state = EvidenceState::start(options).unwrap();
        state
            .record_action(
                "open",
                json!({"url": "https://example.test"}),
                None,
                None,
                None,
            )
            .unwrap();
        state.finalize(CollectedEvidence::default()).unwrap();

        for directory in [
            output.clone(),
            output.join("private"),
            output.join("redacted"),
        ] {
            let mode = fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "wrong permissions for {}", directory.display());
        }

        for file in [
            output.join("manifest.json"),
            output.join("private/actions.jsonl"),
            output.join("redacted/actions.jsonl"),
            output.join("private/network.json"),
            output.join("redacted/network.json"),
        ] {
            let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "wrong permissions for {}", file.display());
        }
    }

    #[test]
    fn default_bundle_is_redacted_only() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("bundle");
        let mut state = EvidenceState::start(EvidenceStartOptions::new(&output)).unwrap();
        state
            .record_action(
                "fill",
                json!({"password": "do-not-write-raw"}),
                None,
                None,
                None,
            )
            .unwrap();
        let manifest = state.finalize(CollectedEvidence::default()).unwrap();
        assert!(!manifest.private_artifacts);
        assert!(!output.join("private").exists());
        assert!(!fs::read_to_string(output.join("redacted/actions.jsonl"))
            .unwrap()
            .contains("do-not-write-raw"));
    }
}
