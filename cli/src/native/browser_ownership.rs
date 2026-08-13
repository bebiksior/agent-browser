//! Persistent ownership records for browser targets.
//!
//! The registry is deliberately separate from daemon PID and socket files so
//! ownership remains visible across daemon restarts. Claims are exclusive by
//! both target and session. This prevents a worker from taking another
//! worker's tab and prevents two workers from silently sharing one session.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REGISTRY_FILE: &str = ".browser-ownership.json";
const REGISTRY_LOCK: &str = ".browser-ownership.lock";
const LOCK_WAIT: Duration = Duration::from_secs(5);
const LOCK_STALE_AFTER: Duration = Duration::from_secs(30);
const MAX_SESSION_LEN: usize = 256;
const MAX_TARGET_LEN: usize = 1024;
const MAX_WORKER_ID_LEN: usize = 512;
const MAX_HOST_LEN: usize = 512;
static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Stable identity for the worker that owns a session or browser lease.
///
/// `id` should be stable for the lifetime of an orchestrated worker. `pid`
/// enables stale-process checks when the worker is local, while `host`
/// prevents a PID from another machine being checked as if it were local.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerIdentity {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl WorkerIdentity {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            pid: None,
            host: None,
        }
    }

    pub fn for_current_process(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            pid: Some(std::process::id()),
            host: local_hostname(),
        }
    }

    /// Compare principals without requiring their process IDs to match. A
    /// stable worker may restart and retain ownership under a new PID.
    pub fn same_principal(&self, other: &Self) -> bool {
        self.id == other.id && self.host == other.host
    }
}

/// One exclusive session-to-target ownership record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserOwner {
    pub session: String,
    pub target_id: String,
    /// Safe diagnostic URL. Credentials, query, and fragment are never stored.
    #[serde(default)]
    pub url: String,
    pub worker: WorkerIdentity,
    pub claimed_at_ms: u64,
    pub updated_at_ms: u64,
}

/// Data supplied when claiming a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRequest {
    pub session: String,
    pub target_id: String,
    pub url: String,
    pub worker: WorkerIdentity,
}

impl OwnershipRequest {
    pub fn new(
        session: impl Into<String>,
        target_id: impl Into<String>,
        url: impl Into<String>,
        worker: WorkerIdentity,
    ) -> Self {
        Self {
            session: session.into(),
            target_id: target_id.into(),
            url: url.into(),
            worker,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipConflictKind {
    TargetOwned,
    SessionOwned,
}

/// Structured refusal data returned without changing the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipConflict {
    pub kind: OwnershipConflictKind,
    pub requested_session: String,
    pub requested_target_id: String,
    pub requested_worker: WorkerIdentity,
    pub existing: BrowserOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClaimOutcome {
    Claimed { owner: BrowserOwner },
    Renewed { owner: BrowserOwner },
    Refused { conflict: OwnershipConflict },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OwnershipReleaseOutcome {
    Released { owner: BrowserOwner },
    NotFound,
    Refused { conflict: OwnershipConflict },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnershipRegistry {
    #[serde(default = "registry_version")]
    version: u32,
    #[serde(default)]
    owners: Vec<BrowserOwner>,
}

fn registry_version() -> u32 {
    1
}

impl Default for OwnershipRegistry {
    fn default() -> Self {
        Self {
            version: registry_version(),
            owners: Vec::new(),
        }
    }
}

/// Path to the persistent ownership registry.
pub fn registry_path() -> PathBuf {
    crate::connection::get_socket_dir().join(REGISTRY_FILE)
}

/// Claim a target for a session and worker.
///
/// Repeating a claim by the same principal renews its timestamp and safe URL.
/// Claiming a different target moves that principal's session ownership.
/// Claims by a different principal are refused if either the target or session
/// is already owned.
pub fn claim(request: OwnershipRequest) -> Result<ClaimOutcome, String> {
    validate_request(&request)?;
    let now = now_ms()?;
    with_registry_lock(REGISTRY_LOCK, || {
        let path = registry_path();
        let mut registry: OwnershipRegistry = read_secure_json(&path)?.unwrap_or_default();
        validate_registry(&registry)?;

        if let Some(existing) = registry
            .owners
            .iter()
            .find(|owner| owner.target_id == request.target_id)
        {
            if existing.session != request.session
                || !existing.worker.same_principal(&request.worker)
            {
                return Ok(ClaimOutcome::Refused {
                    conflict: conflict(OwnershipConflictKind::TargetOwned, &request, existing),
                });
            }
        }

        if let Some(existing) = registry
            .owners
            .iter()
            .find(|owner| owner.session == request.session)
        {
            if !existing.worker.same_principal(&request.worker) {
                return Ok(ClaimOutcome::Refused {
                    conflict: conflict(OwnershipConflictKind::SessionOwned, &request, existing),
                });
            }
        }

        let safe_url = sanitize_url(&request.url);
        let existing_index = registry.owners.iter().position(|owner| {
            owner.session == request.session
                && owner.target_id == request.target_id
                && owner.worker.same_principal(&request.worker)
        });

        let outcome = if let Some(index) = existing_index {
            let owner = &mut registry.owners[index];
            owner.url = safe_url;
            owner.worker = request.worker;
            owner.updated_at_ms = now;
            ClaimOutcome::Renewed {
                owner: owner.clone(),
            }
        } else {
            let owner = BrowserOwner {
                session: request.session,
                target_id: request.target_id,
                url: safe_url,
                worker: request.worker,
                claimed_at_ms: now,
                updated_at_ms: now,
            };
            registry.owners.push(owner.clone());
            ClaimOutcome::Claimed { owner }
        };

        sort_owners(&mut registry.owners);
        atomic_write_json(&path, &registry)?;
        Ok(outcome)
    })
}

/// Convenience wrapper around [`claim`].
pub fn claim_target(
    session: &str,
    target_id: &str,
    url: &str,
    worker: WorkerIdentity,
) -> Result<ClaimOutcome, String> {
    claim(OwnershipRequest::new(session, target_id, url, worker))
}

/// Explicitly replace any conflicting session or target ownership.
///
/// Callers must expose this only through an explicit override such as
/// `--force-ownership`. The replacement is performed under the same registry
/// lock as a normal claim so another worker cannot slip in between release and
/// acquisition.
pub fn force_claim(request: OwnershipRequest) -> Result<ClaimOutcome, String> {
    validate_request(&request)?;
    let now = now_ms()?;
    with_registry_lock(REGISTRY_LOCK, || {
        let path = registry_path();
        let mut registry: OwnershipRegistry = read_secure_json(&path)?.unwrap_or_default();
        validate_registry(&registry)?;

        registry.owners.retain(|owner| {
            owner.target_id != request.target_id
                && (owner.session != request.session
                    || owner.worker.same_principal(&request.worker))
        });
        let owner = BrowserOwner {
            session: request.session,
            target_id: request.target_id,
            url: sanitize_url(&request.url),
            worker: request.worker,
            claimed_at_ms: now,
            updated_at_ms: now,
        };
        registry.owners.push(owner.clone());
        sort_owners(&mut registry.owners);
        atomic_write_json(&path, &registry)?;
        Ok(ClaimOutcome::Claimed { owner })
    })
}

pub fn force_claim_target(
    session: &str,
    target_id: &str,
    url: &str,
    worker: WorkerIdentity,
) -> Result<ClaimOutcome, String> {
    force_claim(OwnershipRequest::new(session, target_id, url, worker))
}

/// Return all ownership records in deterministic session/target order.
pub fn list() -> Result<Vec<BrowserOwner>, String> {
    let mut registry: OwnershipRegistry = read_secure_json(&registry_path())?.unwrap_or_default();
    validate_registry(&registry)?;
    sort_owners(&mut registry.owners);
    Ok(registry.owners)
}

/// Return all owners recorded for a target. A valid registry normally has at
/// most one; a vector keeps inspection useful if a future schema changes this.
pub fn list_by_target(target_id: &str) -> Result<Vec<BrowserOwner>, String> {
    validate_identifier("target id", target_id, MAX_TARGET_LEN)?;
    Ok(list()?
        .into_iter()
        .filter(|owner| owner.target_id == target_id)
        .collect())
}

/// Report a conflict for a proposed claim without modifying the registry.
pub fn detect_conflict(request: &OwnershipRequest) -> Result<Option<OwnershipConflict>, String> {
    validate_request(request)?;
    let registry: OwnershipRegistry = read_secure_json(&registry_path())?.unwrap_or_default();
    validate_registry(&registry)?;

    if let Some(existing) = registry
        .owners
        .iter()
        .find(|owner| owner.target_id == request.target_id)
    {
        if existing.session != request.session || !existing.worker.same_principal(&request.worker) {
            return Ok(Some(conflict(
                OwnershipConflictKind::TargetOwned,
                request,
                existing,
            )));
        }
    }

    Ok(registry
        .owners
        .iter()
        .find(|owner| {
            owner.session == request.session && !owner.worker.same_principal(&request.worker)
        })
        .map(|existing| conflict(OwnershipConflictKind::SessionOwned, request, existing)))
}

/// Release one target. A different worker receives structured refusal data.
pub fn release(
    session: &str,
    target_id: &str,
    worker: &WorkerIdentity,
) -> Result<OwnershipReleaseOutcome, String> {
    validate_identifier("session", session, MAX_SESSION_LEN)?;
    validate_identifier("target id", target_id, MAX_TARGET_LEN)?;
    validate_worker(worker)?;

    with_registry_lock(REGISTRY_LOCK, || {
        let path = registry_path();
        let mut registry: OwnershipRegistry = read_secure_json(&path)?.unwrap_or_default();
        validate_registry(&registry)?;
        let Some(index) = registry
            .owners
            .iter()
            .position(|owner| owner.target_id == target_id)
        else {
            return Ok(OwnershipReleaseOutcome::NotFound);
        };
        let existing = registry.owners[index].clone();
        if existing.session != session || !existing.worker.same_principal(worker) {
            let request = OwnershipRequest::new(session, target_id, "", worker.clone());
            return Ok(OwnershipReleaseOutcome::Refused {
                conflict: conflict(OwnershipConflictKind::TargetOwned, &request, &existing),
            });
        }
        registry.owners.remove(index);
        atomic_write_json(&path, &registry)?;
        Ok(OwnershipReleaseOutcome::Released { owner: existing })
    })
}

/// Release the target owned by a session, if the worker principal matches.
pub fn release_session(
    session: &str,
    worker: &WorkerIdentity,
) -> Result<OwnershipReleaseOutcome, String> {
    validate_identifier("session", session, MAX_SESSION_LEN)?;
    validate_worker(worker)?;

    with_registry_lock(REGISTRY_LOCK, || {
        let path = registry_path();
        let mut registry: OwnershipRegistry = read_secure_json(&path)?.unwrap_or_default();
        validate_registry(&registry)?;
        let Some(first) = registry
            .owners
            .iter()
            .find(|owner| owner.session == session)
            .cloned()
        else {
            return Ok(OwnershipReleaseOutcome::NotFound);
        };
        if !first.worker.same_principal(worker) {
            let request =
                OwnershipRequest::new(session, first.target_id.clone(), "", worker.clone());
            return Ok(OwnershipReleaseOutcome::Refused {
                conflict: conflict(OwnershipConflictKind::SessionOwned, &request, &first),
            });
        }
        registry
            .owners
            .retain(|owner| owner.session != session || !owner.worker.same_principal(worker));
        atomic_write_json(&path, &registry)?;
        Ok(OwnershipReleaseOutcome::Released { owner: first })
    })
}

fn conflict(
    kind: OwnershipConflictKind,
    request: &OwnershipRequest,
    existing: &BrowserOwner,
) -> OwnershipConflict {
    OwnershipConflict {
        kind,
        requested_session: request.session.clone(),
        requested_target_id: request.target_id.clone(),
        requested_worker: request.worker.clone(),
        existing: existing.clone(),
    }
}

fn validate_request(request: &OwnershipRequest) -> Result<(), String> {
    validate_identifier("session", &request.session, MAX_SESSION_LEN)?;
    validate_identifier("target id", &request.target_id, MAX_TARGET_LEN)?;
    validate_worker(&request.worker)
}

fn validate_registry(registry: &OwnershipRegistry) -> Result<(), String> {
    if registry.version != registry_version() {
        return Err(format!(
            "unsupported browser ownership registry version {}",
            registry.version
        ));
    }
    for owner in &registry.owners {
        validate_identifier("session", &owner.session, MAX_SESSION_LEN)?;
        validate_identifier("target id", &owner.target_id, MAX_TARGET_LEN)?;
        validate_worker(&owner.worker)?;
        if owner.url != sanitize_url(&owner.url) {
            return Err("browser ownership registry contains an unsafe URL".to_string());
        }
    }
    for (index, owner) in registry.owners.iter().enumerate() {
        if registry.owners[index + 1..]
            .iter()
            .any(|candidate| candidate.target_id == owner.target_id)
        {
            return Err(format!(
                "browser ownership registry contains duplicate target '{}'",
                owner.target_id
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_worker(worker: &WorkerIdentity) -> Result<(), String> {
    validate_identifier("worker id", &worker.id, MAX_WORKER_ID_LEN)?;
    if worker.pid.is_some_and(|pid| !process_id_is_valid(pid)) {
        return Err("worker pid is outside the platform process-id range".to_string());
    }
    if let Some(host) = &worker.host {
        validate_identifier("worker host", host, MAX_HOST_LEN)?;
    }
    Ok(())
}

pub(crate) fn validate_identifier(label: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} cannot be empty", label));
    }
    if value.len() > max_len {
        return Err(format!("{} exceeds {} bytes", label, max_len));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{} contains control characters", label));
    }
    Ok(())
}

fn sort_owners(owners: &mut [BrowserOwner]) {
    owners.sort_by(|a, b| {
        a.session
            .cmp(&b.session)
            .then_with(|| a.target_id.cmp(&b.target_id))
    });
}

/// Reduce a URL to non-secret diagnostic data before persistence.
pub fn sanitize_url(raw: &str) -> String {
    if raw == "about:blank" {
        return raw.to_string();
    }
    match url::Url::parse(raw) {
        Ok(mut parsed) if matches!(parsed.scheme(), "http" | "https") => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        _ => String::new(),
    }
}

pub(crate) fn now_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock is before unix epoch: {}", e))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system timestamp exceeds u64".to_string())
}

pub(crate) fn local_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .filter(|host| !host.is_empty() && !host.chars().any(char::is_control))
}

pub(crate) fn is_worker_process_alive(worker: &WorkerIdentity) -> Option<bool> {
    let pid = worker.pid?;
    if !process_id_is_valid(pid) {
        return Some(false);
    }
    if worker
        .host
        .as_ref()
        .is_some_and(|host| Some(host) != local_hostname().as_ref())
    {
        return None;
    }
    Some(crate::connection::is_pid_alive(pid))
}

fn process_id_is_valid(pid: u32) -> bool {
    #[cfg(unix)]
    {
        pid > 0 && pid <= i32::MAX as u32
    }
    #[cfg(windows)]
    {
        pid > 0
    }
}

pub(crate) fn read_secure_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot inspect {}: {}", path.display(), e)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "refusing non-regular registry file {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(format!(
                "registry file {} has a different owner",
                path.display()
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "registry file {} is not owner-only",
                path.display()
            ));
        }
    }
    let raw = fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|e| format!("corrupt registry file {}: {}", path.display(), e))
}

pub(crate) fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut raw = serde_json::to_vec(value)
        .map_err(|e| format!("cannot serialize registry {}: {}", path.display(), e))?;
    raw.push(b'\n');
    let dir = path
        .parent()
        .ok_or_else(|| format!("registry path {} has no parent", path.display()))?;
    create_secure_dir(dir)?;
    let tmp = unique_temp_path(path);
    let write_result = (|| -> Result<(), String> {
        let mut file = secure_create_new(&tmp)?;
        file.write_all(&raw)
            .map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
        file.sync_all()
            .map_err(|e| format!("cannot sync {}: {}", tmp.display(), e))?;
        drop(file);
        atomic_replace(&tmp, path)?;
        sync_directory(dir)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

pub(crate) fn with_registry_lock<T, F>(lock_name: &str, operation: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let dir = crate::connection::get_socket_dir();
    create_secure_dir(&dir)?;
    let lock = RegistryLock::acquire(dir.join(lock_name), LOCK_WAIT)?;
    let result = operation();
    drop(lock);
    result
}

fn create_secure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|e| format!("cannot create socket dir {}: {}", path.display(), e))?;
    Ok(())
}

fn secure_create_new(path: &Path) -> Result<File, String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| format!("cannot create owner-only file {}: {}", path.display(), e))
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let counter = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    path.with_file_name(format!(".{}.tmp.{}.{}", name, std::process::id(), counter))
}

#[cfg(not(windows))]
fn atomic_replace(from: &Path, to: &Path) -> Result<(), String> {
    fs::rename(from, to).map_err(|e| {
        format!(
            "cannot atomically replace {} with {}: {}",
            to.display(),
            from.display(),
            e
        )
    })
}

#[cfg(windows)]
fn atomic_replace(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(format!(
            "cannot atomically replace registry file: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("cannot sync directory {}: {}", path.display(), e))?;
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockRecord {
    pid: u32,
    created_at_ms: u64,
    token: String,
}

struct RegistryLock {
    path: PathBuf,
    token: String,
}

impl RegistryLock {
    fn acquire(path: PathBuf, timeout: Duration) -> Result<Self, String> {
        let started = std::time::Instant::now();
        loop {
            let token = format!(
                "{}-{}-{}",
                std::process::id(),
                now_ms()?,
                FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            match secure_create_new(&path) {
                Ok(mut file) => {
                    let record = LockRecord {
                        pid: std::process::id(),
                        created_at_ms: now_ms()?,
                        token: token.clone(),
                    };
                    let raw = serde_json::to_vec(&record)
                        .map_err(|e| format!("cannot serialize registry lock: {}", e))?;
                    if let Err(e) = file.write_all(&raw).and_then(|_| file.sync_all()) {
                        let _ = fs::remove_file(&path);
                        return Err(format!("cannot initialize lock {}: {}", path.display(), e));
                    }
                    return Ok(Self { path, token });
                }
                Err(_) => {
                    if lock_is_stale(&path)? {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() >= timeout {
                        return Err(format!(
                            "timed out waiting for registry lock {}",
                            path.display()
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

impl Drop for RegistryLock {
    fn drop(&mut self) {
        let owned = fs::read(&self.path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<LockRecord>(&raw).ok())
            .is_some_and(|record| record.token == self.token);
        if owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn lock_is_stale(path: &Path) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("cannot inspect lock {}: {}", path.display(), e)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("refusing unsafe lock file {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "refusing lock file {} that is not owner-only",
                path.display()
            ));
        }
    }
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("cannot read lock {}: {}", path.display(), e)),
    };
    if let Ok(record) = serde_json::from_slice::<LockRecord>(&raw) {
        if !process_id_is_valid(record.pid) {
            return Ok(true);
        }
        let age = now_ms()?.saturating_sub(record.created_at_ms);
        return Ok(age >= LOCK_STALE_AFTER.as_millis() as u64
            || !crate::connection::is_pid_alive(record.pid));
    }
    let age = metadata
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok());
    Ok(age.is_some_and(|age| age >= LOCK_STALE_AFTER))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_socket_dir<F: FnOnce(&Path)>(f: F) {
        let guard = crate::test_utils::EnvGuard::new(&[
            "AGENT_BROWSER_SOCKET_DIR",
            "XDG_RUNTIME_DIR",
            "AGENT_BROWSER_NAMESPACE",
        ]);
        let dir = tempfile::tempdir().unwrap();
        guard.set("AGENT_BROWSER_SOCKET_DIR", dir.path().to_str().unwrap());
        guard.remove("XDG_RUNTIME_DIR");
        guard.remove("AGENT_BROWSER_NAMESPACE");
        f(dir.path());
    }

    fn worker(id: &str) -> WorkerIdentity {
        WorkerIdentity::new(id)
    }

    #[test]
    fn claim_round_trip_and_list_by_target() {
        with_socket_dir(|_| {
            let result = claim_target(
                "agent-a",
                "target-a",
                "https://user:secret@example.com/a?token=x#secret",
                worker("worker-a"),
            )
            .unwrap();
            let owner = match result {
                ClaimOutcome::Claimed { owner } => owner,
                other => panic!("unexpected outcome: {other:?}"),
            };
            assert_eq!(owner.url, "https://example.com/a");
            assert_eq!(list_by_target("target-a").unwrap(), vec![owner]);
        });
    }

    #[test]
    fn refuses_target_owned_by_another_worker() {
        with_socket_dir(|_| {
            claim_target("agent-a", "target-a", "about:blank", worker("worker-a")).unwrap();
            let result =
                claim_target("agent-b", "target-a", "about:blank", worker("worker-b")).unwrap();
            let ClaimOutcome::Refused { conflict } = result else {
                panic!("claim should be refused");
            };
            assert_eq!(conflict.kind, OwnershipConflictKind::TargetOwned);
            assert_eq!(conflict.existing.session, "agent-a");
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn refuses_session_shared_by_another_worker() {
        with_socket_dir(|_| {
            claim_target("agent-a", "target-a", "", worker("worker-a")).unwrap();
            let result = claim_target("agent-a", "target-b", "", worker("worker-b")).unwrap();
            let ClaimOutcome::Refused { conflict } = result else {
                panic!("claim should be refused");
            };
            assert_eq!(conflict.kind, OwnershipConflictKind::SessionOwned);
            assert_eq!(conflict.existing.target_id, "target-a");
        });
    }

    #[test]
    fn same_worker_can_own_multiple_targets_in_one_session() {
        with_socket_dir(|_| {
            let principal = worker("worker-a");
            claim_target("agent-a", "target-a", "", principal.clone()).unwrap();
            let result = claim_target("agent-a", "target-b", "", principal).unwrap();
            assert!(matches!(result, ClaimOutcome::Claimed { .. }));
            assert_eq!(list_by_target("target-a").unwrap().len(), 1);
            assert_eq!(list_by_target("target-b").unwrap().len(), 1);
        });
    }

    #[test]
    fn release_refuses_a_different_worker() {
        with_socket_dir(|_| {
            claim_target("agent-a", "target-a", "", worker("worker-a")).unwrap();
            let outcome = release("agent-a", "target-a", &worker("worker-b")).unwrap();
            assert!(matches!(outcome, OwnershipReleaseOutcome::Refused { .. }));
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn release_by_owner_removes_record() {
        with_socket_dir(|_| {
            let principal = worker("worker-a");
            claim_target("agent-a", "target-a", "", principal.clone()).unwrap();
            let outcome = release_session("agent-a", &principal).unwrap();
            assert!(matches!(outcome, OwnershipReleaseOutcome::Released { .. }));
            assert!(list().unwrap().is_empty());
        });
    }

    #[test]
    fn persisted_url_never_contains_secrets() {
        with_socket_dir(|_| {
            claim_target(
                "agent-a",
                "target-a",
                "data:text/html,persisted-secret",
                worker("worker-a"),
            )
            .unwrap();
            let raw = fs::read_to_string(registry_path()).unwrap();
            assert!(!raw.contains("persisted-secret"));
            assert_eq!(list().unwrap()[0].url, "");
        });
    }

    #[test]
    fn rejects_invalid_process_id() {
        with_socket_dir(|_| {
            let principal = WorkerIdentity {
                id: "worker-a".to_string(),
                pid: Some(0),
                host: None,
            };
            let error = claim_target("agent-a", "target-a", "", principal).unwrap_err();
            assert!(error.contains("process-id range"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn registry_and_lock_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        with_socket_dir(|_| {
            claim_target("agent-a", "target-a", "", worker("worker-a")).unwrap();
            let mode = fs::metadata(registry_path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            assert!(!crate::connection::get_socket_dir()
                .join(REGISTRY_LOCK)
                .exists());
        });
    }

    #[test]
    fn corrupt_registry_is_not_silently_replaced() {
        with_socket_dir(|_| {
            let path = registry_path();
            fs::write(&path, "not-json").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let error = list().unwrap_err();
            assert!(error.contains("corrupt registry"), "{error}");
        });
    }

    #[test]
    fn stale_lock_is_recovered() {
        with_socket_dir(|dir| {
            let lock = dir.join(REGISTRY_LOCK);
            let record = LockRecord {
                pid: std::process::id(),
                created_at_ms: 0,
                token: "stale".to_string(),
            };
            atomic_write_json(&lock, &record).unwrap();
            claim_target("agent-a", "target-a", "", worker("worker-a")).unwrap();
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn concurrent_claims_leave_one_owner() {
        with_socket_dir(|_| {
            let handles: Vec<_> = (0..8)
                .map(|index| {
                    thread::spawn(move || {
                        claim_target(
                            &format!("agent-{index}"),
                            "shared-target",
                            "",
                            worker(&format!("worker-{index}")),
                        )
                        .unwrap()
                    })
                })
                .collect();
            let outcomes: Vec<_> = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| matches!(outcome, ClaimOutcome::Claimed { .. }))
                    .count(),
                1
            );
            assert_eq!(list().unwrap().len(), 1);
        });
    }
}
