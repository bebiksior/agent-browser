//! Persistent exclusive leases for browser profiles.
//!
//! A lease prevents two independently orchestrated workers from launching or
//! attaching to the same profile without an explicit handoff. Leases expire,
//! can be renewed by their owner, and are also considered stale when a local
//! owner PID is known to be gone.

use super::browser_ownership::{
    atomic_write_json, is_worker_process_alive, now_ms, read_secure_json, validate_identifier,
    validate_worker, with_registry_lock, WorkerIdentity,
};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const REGISTRY_FILE: &str = ".browser-leases.json";
const REGISTRY_LOCK: &str = ".browser-leases.lock";
const MAX_SESSION_LEN: usize = 256;
const MAX_PROFILE_LEN: usize = 4096;
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(120);

/// Session, profile, and worker identity used for lease operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseIdentity {
    pub session: String,
    /// Absolute normalized profile path. `None` identifies the default
    /// temporary profile and is scoped by `session` because each session gets
    /// a distinct directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub worker: WorkerIdentity,
}

impl LeaseIdentity {
    pub fn new<P: Into<String>>(
        session: impl Into<String>,
        profile: Option<P>,
        worker: WorkerIdentity,
    ) -> Self {
        Self {
            session: session.into(),
            profile: profile.map(Into::into),
            worker,
        }
    }

    fn same_owner(&self, other: &Self) -> bool {
        self.session == other.session
            && self.profile == other.profile
            && self.worker.same_principal(&other.worker)
    }

    fn same_scope(&self, other: &Self) -> bool {
        match (&self.profile, &other.profile) {
            (Some(left), Some(right)) => left == right,
            (None, None) => self.session == other.session,
            _ => false,
        }
    }
}

/// One persisted browser lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserLease {
    #[serde(flatten)]
    pub identity: LeaseIdentity,
    pub acquired_at_ms: u64,
    pub renewed_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleLeaseReason {
    Expired,
    ProcessGone,
    ExpiredAndProcessGone,
}

/// Structured refusal data for a live lease held by another identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseConflict {
    pub requested: LeaseIdentity,
    pub existing: BrowserLease,
    pub remaining_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AcquireOutcome {
    Acquired {
        lease: BrowserLease,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replaced_stale: Option<BrowserLease>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stale_reason: Option<StaleLeaseReason>,
    },
    Renewed {
        lease: BrowserLease,
    },
    Refused {
        conflict: LeaseConflict,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LeaseStatus {
    Available,
    Held {
        lease: BrowserLease,
        owned_by_requester: bool,
        remaining_ms: u64,
    },
    Stale {
        lease: BrowserLease,
        owned_by_requester: bool,
        reason: StaleLeaseReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LeaseReleaseOutcome {
    Released { lease: BrowserLease },
    NotFound,
    Refused { conflict: LeaseConflict },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeaseRegistry {
    #[serde(default = "registry_version")]
    version: u32,
    #[serde(default)]
    leases: Vec<BrowserLease>,
}

fn registry_version() -> u32 {
    1
}

impl Default for LeaseRegistry {
    fn default() -> Self {
        Self {
            version: registry_version(),
            leases: Vec::new(),
        }
    }
}

/// Path to the persistent browser lease registry.
pub fn registry_path() -> PathBuf {
    crate::connection::get_socket_dir().join(REGISTRY_FILE)
}

/// Normalize an optional profile path into a stable identity.
pub fn normalize_profile_identity(profile: Option<&str>) -> Result<Option<String>, String> {
    let Some(profile) = profile else {
        return Ok(None);
    };
    validate_identifier("profile", profile, MAX_PROFILE_LEN)?;
    let path = Path::new(profile);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current directory for profile: {}", e))?
            .join(path)
    };
    let normalized = absolute
        .canonicalize()
        .unwrap_or_else(|_| lexical_normalize(&absolute));
    let value = normalized.to_string_lossy().to_string();
    validate_identifier("profile", &value, MAX_PROFILE_LEN)?;
    Ok(Some(value))
}

/// Acquire or renew an exclusive lease.
///
/// A live lease held by another identity is returned as `Refused`. An expired
/// lease or one whose local owner process is gone is replaced atomically and
/// returned in `replaced_stale` for diagnostics.
pub fn acquire(identity: LeaseIdentity, ttl: Duration) -> Result<AcquireOutcome, String> {
    let identity = normalize_identity(identity)?;
    let ttl_ms = validate_ttl(ttl)?;
    let now = now_ms()?;

    with_registry_lock(REGISTRY_LOCK, || {
        let path = registry_path();
        let mut registry: LeaseRegistry = read_secure_json(&path)?.unwrap_or_default();
        validate_registry(&registry)?;
        let existing_index = registry
            .leases
            .iter()
            .position(|lease| lease.identity.same_scope(&identity));

        let outcome = if let Some(index) = existing_index {
            let existing = registry.leases[index].clone();
            if existing.identity.same_owner(&identity) {
                let lease = &mut registry.leases[index];
                lease.identity.worker = identity.worker;
                lease.renewed_at_ms = now;
                lease.expires_at_ms = now.saturating_add(ttl_ms);
                AcquireOutcome::Renewed {
                    lease: lease.clone(),
                }
            } else if let Some(reason) = stale_reason(&existing, now) {
                let lease = new_lease(identity, now, ttl_ms);
                registry.leases[index] = lease.clone();
                AcquireOutcome::Acquired {
                    lease,
                    replaced_stale: Some(existing),
                    stale_reason: Some(reason),
                }
            } else {
                return Ok(AcquireOutcome::Refused {
                    conflict: LeaseConflict {
                        requested: identity,
                        remaining_ms: existing.expires_at_ms.saturating_sub(now),
                        existing,
                    },
                });
            }
        } else {
            let lease = new_lease(identity, now, ttl_ms);
            registry.leases.push(lease.clone());
            AcquireOutcome::Acquired {
                lease,
                replaced_stale: None,
                stale_reason: None,
            }
        };

        sort_leases(&mut registry.leases);
        atomic_write_json(&path, &registry)?;
        Ok(outcome)
    })
}

/// Acquire a lease with [`DEFAULT_LEASE_TTL`].
pub fn acquire_default(identity: LeaseIdentity) -> Result<AcquireOutcome, String> {
    acquire(identity, DEFAULT_LEASE_TTL)
}

/// Inspect the lease for an identity's profile without modifying it.
pub fn status(identity: &LeaseIdentity) -> Result<LeaseStatus, String> {
    let identity = normalize_identity(identity.clone())?;
    let registry: LeaseRegistry = read_secure_json(&registry_path())?.unwrap_or_default();
    validate_registry(&registry)?;
    let Some(lease) = registry
        .leases
        .into_iter()
        .find(|lease| lease.identity.same_scope(&identity))
    else {
        return Ok(LeaseStatus::Available);
    };
    let owned_by_requester = lease.identity.same_owner(&identity);
    let now = now_ms()?;
    if let Some(reason) = stale_reason(&lease, now) {
        return Ok(LeaseStatus::Stale {
            lease,
            owned_by_requester,
            reason,
        });
    }
    let remaining_ms = lease.expires_at_ms.saturating_sub(now);
    Ok(LeaseStatus::Held {
        lease,
        owned_by_requester,
        remaining_ms,
    })
}

/// Release a lease only when session, profile, and worker principal match.
pub fn release(identity: &LeaseIdentity) -> Result<LeaseReleaseOutcome, String> {
    let identity = normalize_identity(identity.clone())?;
    with_registry_lock(REGISTRY_LOCK, || {
        let path = registry_path();
        let mut registry: LeaseRegistry = read_secure_json(&path)?.unwrap_or_default();
        validate_registry(&registry)?;
        let Some(index) = registry
            .leases
            .iter()
            .position(|lease| lease.identity.same_scope(&identity))
        else {
            return Ok(LeaseReleaseOutcome::NotFound);
        };
        let existing = registry.leases[index].clone();
        if !existing.identity.same_owner(&identity) {
            return Ok(LeaseReleaseOutcome::Refused {
                conflict: LeaseConflict {
                    requested: identity,
                    remaining_ms: existing.expires_at_ms.saturating_sub(now_ms()?),
                    existing,
                },
            });
        }
        registry.leases.remove(index);
        atomic_write_json(&path, &registry)?;
        Ok(LeaseReleaseOutcome::Released { lease: existing })
    })
}

/// Return every lease in deterministic profile/session order.
pub fn list() -> Result<Vec<BrowserLease>, String> {
    let mut registry: LeaseRegistry = read_secure_json(&registry_path())?.unwrap_or_default();
    validate_registry(&registry)?;
    sort_leases(&mut registry.leases);
    Ok(registry.leases)
}

fn normalize_identity(mut identity: LeaseIdentity) -> Result<LeaseIdentity, String> {
    validate_identifier("session", &identity.session, MAX_SESSION_LEN)?;
    validate_worker(&identity.worker)?;
    identity.profile = normalize_profile_identity(identity.profile.as_deref())?;
    Ok(identity)
}

fn new_lease(identity: LeaseIdentity, now: u64, ttl_ms: u64) -> BrowserLease {
    BrowserLease {
        identity,
        acquired_at_ms: now,
        renewed_at_ms: now,
        expires_at_ms: now.saturating_add(ttl_ms),
    }
}

fn validate_ttl(ttl: Duration) -> Result<u64, String> {
    let millis = ttl.as_millis();
    if millis == 0 {
        return Err("browser lease ttl must be at least one millisecond".to_string());
    }
    u64::try_from(millis).map_err(|_| "browser lease ttl exceeds u64 milliseconds".to_string())
}

fn validate_registry(registry: &LeaseRegistry) -> Result<(), String> {
    if registry.version != registry_version() {
        return Err(format!(
            "unsupported browser lease registry version {}",
            registry.version
        ));
    }
    for lease in &registry.leases {
        let normalized = normalize_identity(lease.identity.clone())?;
        if normalized != lease.identity {
            return Err("browser lease registry contains a non-normalized profile".to_string());
        }
        if lease.acquired_at_ms > lease.renewed_at_ms || lease.renewed_at_ms >= lease.expires_at_ms
        {
            return Err("browser lease registry contains invalid timestamps".to_string());
        }
    }
    for (index, lease) in registry.leases.iter().enumerate() {
        if registry.leases[index + 1..]
            .iter()
            .any(|candidate| candidate.identity.same_scope(&lease.identity))
        {
            return Err("browser lease registry contains duplicate lease scopes".to_string());
        }
    }
    Ok(())
}

fn stale_reason(lease: &BrowserLease, now: u64) -> Option<StaleLeaseReason> {
    stale_reason_from_state(
        now >= lease.expires_at_ms,
        is_worker_process_alive(&lease.identity.worker),
    )
}

fn stale_reason_from_state(expired: bool, process_alive: Option<bool>) -> Option<StaleLeaseReason> {
    match (expired, process_alive) {
        (true, Some(false)) => Some(StaleLeaseReason::ExpiredAndProcessGone),
        (true, _) => Some(StaleLeaseReason::Expired),
        (false, Some(false)) => Some(StaleLeaseReason::ProcessGone),
        (false, _) => None,
    }
}

fn sort_leases(leases: &mut [BrowserLease]) {
    leases.sort_by(|a, b| {
        a.identity
            .profile
            .cmp(&b.identity.profile)
            .then_with(|| a.identity.session.cmp(&b.identity.session))
    });
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;

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

    fn identity(session: &str, profile: Option<&str>, worker: &str) -> LeaseIdentity {
        LeaseIdentity::new(
            session,
            profile.map(str::to_string),
            WorkerIdentity::new(worker),
        )
    }

    #[test]
    fn acquire_status_release_round_trip() {
        with_socket_dir(|dir| {
            let profile = dir.join("profile");
            let requested = identity("agent-a", profile.to_str(), "worker-a");
            let outcome = acquire(requested.clone(), Duration::from_secs(60)).unwrap();
            assert!(matches!(
                outcome,
                AcquireOutcome::Acquired {
                    replaced_stale: None,
                    ..
                }
            ));
            assert!(matches!(
                status(&requested).unwrap(),
                LeaseStatus::Held {
                    owned_by_requester: true,
                    ..
                }
            ));
            assert!(matches!(
                release(&requested).unwrap(),
                LeaseReleaseOutcome::Released { .. }
            ));
            assert_eq!(status(&requested).unwrap(), LeaseStatus::Available);
        });
    }

    #[test]
    fn live_lease_refuses_another_worker() {
        with_socket_dir(|dir| {
            let profile = dir.join("profile");
            let first = identity("agent-a", profile.to_str(), "worker-a");
            let second = identity("agent-b", profile.to_str(), "worker-b");
            acquire(first, Duration::from_secs(60)).unwrap();
            let result = acquire(second, Duration::from_secs(60)).unwrap();
            let AcquireOutcome::Refused { conflict } = result else {
                panic!("acquire should be refused");
            };
            assert_eq!(conflict.existing.identity.session, "agent-a");
            assert!(conflict.remaining_ms > 0);
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn owner_renewal_preserves_acquired_timestamp() {
        with_socket_dir(|dir| {
            let requested = identity("agent-a", dir.join("profile").to_str(), "worker-a");
            let first = match acquire(requested.clone(), Duration::from_secs(60)).unwrap() {
                AcquireOutcome::Acquired { lease, .. } => lease,
                other => panic!("unexpected outcome: {other:?}"),
            };
            let second = match acquire(requested, Duration::from_secs(120)).unwrap() {
                AcquireOutcome::Renewed { lease } => lease,
                other => panic!("unexpected outcome: {other:?}"),
            };
            assert_eq!(first.acquired_at_ms, second.acquired_at_ms);
            assert!(second.expires_at_ms >= first.expires_at_ms);
        });
    }

    #[test]
    fn expired_lease_is_replaced_with_diagnostics() {
        with_socket_dir(|dir| {
            let profile = normalize_profile_identity(dir.join("profile").to_str()).unwrap();
            let stale = BrowserLease {
                identity: LeaseIdentity {
                    session: "agent-a".to_string(),
                    profile: profile.clone(),
                    worker: WorkerIdentity::new("worker-a"),
                },
                acquired_at_ms: 1,
                renewed_at_ms: 1,
                expires_at_ms: 2,
            };
            let registry = LeaseRegistry {
                version: 1,
                leases: vec![stale.clone()],
            };
            atomic_write_json(&registry_path(), &registry).unwrap();

            let next = LeaseIdentity {
                session: "agent-b".to_string(),
                profile,
                worker: WorkerIdentity::new("worker-b"),
            };
            let result = acquire(next, Duration::from_secs(60)).unwrap();
            let AcquireOutcome::Acquired {
                replaced_stale,
                stale_reason,
                ..
            } = result
            else {
                panic!("stale lease should be replaced");
            };
            assert_eq!(replaced_stale, Some(stale));
            assert_eq!(stale_reason, Some(StaleLeaseReason::Expired));
        });
    }

    #[test]
    fn stale_reason_combines_expiry_and_process_liveness() {
        assert_eq!(
            stale_reason_from_state(true, Some(false)),
            Some(StaleLeaseReason::ExpiredAndProcessGone)
        );
        assert_eq!(
            stale_reason_from_state(false, Some(false)),
            Some(StaleLeaseReason::ProcessGone)
        );
        assert_eq!(
            stale_reason_from_state(true, None),
            Some(StaleLeaseReason::Expired)
        );
        assert_eq!(stale_reason_from_state(false, None), None);
    }

    #[test]
    fn release_refuses_another_identity() {
        with_socket_dir(|dir| {
            let profile = dir.join("profile");
            let first = identity("agent-a", profile.to_str(), "worker-a");
            let second = identity("agent-b", profile.to_str(), "worker-b");
            acquire(first, Duration::from_secs(60)).unwrap();
            assert!(matches!(
                release(&second).unwrap(),
                LeaseReleaseOutcome::Refused { .. }
            ));
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn equivalent_profile_paths_share_one_identity() {
        with_socket_dir(|dir| {
            let direct = dir.join("profiles").join("one");
            let aliased = dir.join("profiles").join("two").join("..").join("one");
            let first = identity("agent-a", direct.to_str(), "worker-a");
            let second = identity("agent-b", aliased.to_str(), "worker-b");
            acquire(first, Duration::from_secs(60)).unwrap();
            assert!(matches!(
                acquire(second, Duration::from_secs(60)).unwrap(),
                AcquireOutcome::Refused { .. }
            ));
        });
    }

    #[test]
    fn default_profiles_are_scoped_by_session() {
        with_socket_dir(|_| {
            acquire(
                identity("agent-a", None, "worker-a"),
                Duration::from_secs(60),
            )
            .unwrap();
            assert!(matches!(
                acquire(
                    identity("agent-a", None, "worker-b"),
                    Duration::from_secs(60)
                )
                .unwrap(),
                AcquireOutcome::Refused { .. }
            ));
            assert!(matches!(
                acquire(
                    identity("agent-b", None, "worker-b"),
                    Duration::from_secs(60)
                )
                .unwrap(),
                AcquireOutcome::Acquired { .. }
            ));
            assert_eq!(list().unwrap().len(), 2);
        });
    }

    #[test]
    fn ttl_must_be_positive() {
        with_socket_dir(|_| {
            let error = acquire(identity("agent-a", None, "worker-a"), Duration::ZERO).unwrap_err();
            assert!(error.contains("at least one millisecond"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn lease_registry_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        with_socket_dir(|_| {
            acquire(
                identity("agent-a", None, "worker-a"),
                Duration::from_secs(60),
            )
            .unwrap();
            let mode = fs::metadata(registry_path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
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
            assert!(list().unwrap_err().contains("corrupt registry"));
        });
    }

    #[test]
    fn concurrent_acquire_has_one_winner() {
        with_socket_dir(|dir| {
            let profile = dir.join("profile").to_string_lossy().to_string();
            let handles: Vec<_> = (0..8)
                .map(|index| {
                    let profile = profile.clone();
                    thread::spawn(move || {
                        acquire(
                            identity(
                                &format!("agent-{index}"),
                                Some(&profile),
                                &format!("worker-{index}"),
                            ),
                            Duration::from_secs(60),
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
                    .filter(|outcome| matches!(outcome, AcquireOutcome::Acquired { .. }))
                    .count(),
                1
            );
            assert_eq!(list().unwrap().len(), 1);
        });
    }
}
