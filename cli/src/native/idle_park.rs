//! Parks a browser nobody is driving.
//!
//! A visible tab is never throttled, so a page that animates, plays video or
//! renders WebGL keeps whole cores busy while the agent thinks. After
//! `AGENT_BROWSER_IDLE_BACKGROUND_MS` without a command the daemon opens a
//! blank cover tab, which puts the page in the background exactly as a person
//! switching tabs would: its scripts keep running, throttled. A page that
//! still keeps the browser above `AGENT_BROWSER_IDLE_FREEZE_CPU` percent of a
//! core is then frozen. The next command undoes all of it before it runs.

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::actions::DaemonState;
use super::cdp::client::CdpClient;
use super::stream::IdleActivity;

/// Not tracked as a tab (see `should_track_target`), so agents never see it.
const COVER_URL: &str = "chrome://version/";
const TICK: Duration = Duration::from_secs(1);
const CDP_TIMEOUT: Duration = Duration::from_secs(2);
const SETTLE: Duration = Duration::from_secs(10);
const PROBE: Duration = Duration::from_secs(20);
const DEFAULT_FREEZE_CPU_PERCENT: f64 = 20.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Config {
    after: Duration,
    /// Percent of one core; 0 never freezes.
    freeze_cpu: f64,
}

impl Config {
    pub(crate) fn from_env() -> Option<Self> {
        Self::parse(
            env::var("AGENT_BROWSER_IDLE_BACKGROUND_MS").ok().as_deref(),
            env::var("AGENT_BROWSER_IDLE_FREEZE_CPU").ok().as_deref(),
        )
    }

    fn parse(after_ms: Option<&str>, freeze_cpu: Option<&str>) -> Option<Self> {
        let after_ms = after_ms?.trim().parse::<u64>().ok().filter(|ms| *ms > 0)?;
        let freeze_cpu = freeze_cpu
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .unwrap_or(DEFAULT_FREEZE_CPU_PERCENT);
        Some(Self {
            after: Duration::from_millis(after_ms),
            freeze_cpu,
        })
    }
}

#[derive(Default)]
pub(crate) struct Parked {
    since: Option<Instant>,
    cover: Option<String>,
    /// Targets the cover tab hid, to bring back in this order.
    restore: Vec<String>,
    frozen: Vec<String>,
    probe: Option<(Instant, u64)>,
}

impl Parked {
    pub(crate) fn has_frozen(&self) -> bool {
        !self.frozen.is_empty()
    }
}

pub(crate) fn spawn(state: Arc<tokio::sync::Mutex<DaemonState>>, activity: Arc<IdleActivity>) {
    let Some(config) = Config::from_env() else {
        return;
    };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            // A held lock is a command in progress, which is not idle.
            let Ok(mut state) = state.try_lock() else {
                continue;
            };
            let idle = activity.elapsed();
            match state.idle_park.since {
                // Dashboard input marks activity without taking the command path.
                Some(since) if idle < since.elapsed() => resume(&mut state).await,
                Some(_) => freeze_if_busy(&mut state, config.freeze_cpu).await,
                None if idle >= config.after => park(&mut state).await,
                None => {}
            }
        }
    });
}

async fn park(state: &mut DaemonState) {
    // Until the next command, whatever happens: one attempt per idle period.
    state.idle_park = Parked {
        since: Some(Instant::now()),
        ..Parked::default()
    };
    if state.recording_state.active {
        return;
    }
    let Some(browser) = state.browser.as_ref() else {
        return;
    };
    if browser.chrome_pid().is_none() {
        return;
    }
    let client = browser.client.clone();
    let pages: Vec<(String, String)> = browser
        .pages_list()
        .into_iter()
        .filter(|page| page.target_type == "page")
        .map(|page| (page.target_id, page.session_id))
        .collect();
    let active = browser.active_target_id().ok().map(str::to_string);

    let mut visible = Vec::new();
    for (target, session) in &pages {
        if visibility(&client, session).await.as_deref() == Some("visible") {
            visible.push((target.clone(), session.clone()));
        }
    }
    if visible.is_empty() {
        return;
    }
    let Some(cover) = send(
        &client,
        "Target.createTarget",
        json!({ "url": COVER_URL, "background": false }),
        None,
    )
    .await
    .and_then(|v| {
        v.get("targetId")
            .and_then(Value::as_str)
            .map(str::to_string)
    }) else {
        return;
    };
    let mut restore = Vec::new();
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        restore.clear();
        for (target, session) in &visible {
            if visibility(&client, session).await.as_deref() == Some("hidden") {
                restore.push(target.clone());
            }
        }
        if !restore.is_empty() {
            break;
        }
    }
    if restore.is_empty() {
        close_target(&client, &cover).await;
        return;
    }
    // The agent's own tab last, so it ends up in front.
    restore.sort_by_key(|target| Some(target) == active.as_ref());
    state.idle_park.cover = Some(cover);
    state.idle_park.restore = restore;
}

async fn freeze_if_busy(state: &mut DaemonState, threshold: f64) {
    let Some(since) = state.idle_park.since else {
        return;
    };
    if threshold <= 0.0
        || state.idle_park.cover.is_none()
        || state.idle_park.has_frozen()
        || since.elapsed() < SETTLE
    {
        return;
    }
    // Each of these was started to watch what the page does over time.
    if state.evidence.is_some() || state.har_recording || state.has_postmessage_monitor() {
        return;
    }
    let Some(browser) = state.browser.as_ref() else {
        return;
    };
    let Some(ticks) = browser.chrome_pid().and_then(tree_cpu_ticks) else {
        return;
    };
    let Some((started, before)) = state.idle_park.probe else {
        state.idle_park.probe = Some((Instant::now(), ticks));
        return;
    };
    let elapsed = started.elapsed();
    if elapsed < PROBE {
        return;
    }
    state.idle_park.probe = Some((Instant::now(), ticks));
    if cpu_percent(ticks.saturating_sub(before), elapsed) < threshold {
        return;
    }
    let client = browser.client.clone();
    let sessions: Vec<String> = browser
        .pages_list()
        .into_iter()
        .filter(|page| page.target_type == "page")
        .map(|page| page.session_id)
        .collect();
    for session in sessions {
        // Freezing forces a page hidden and nothing but a tab switch shows it
        // again, so only pages that are already in the background qualify.
        if visibility(&client, &session).await.as_deref() != Some("hidden") {
            continue;
        }
        let frozen = send(
            &client,
            "Page.setWebLifecycleState",
            json!({ "state": "frozen" }),
            Some(&session),
        )
        .await;
        if frozen.is_some() {
            state.idle_park.frozen.push(session);
        }
    }
}

/// Puts the browser back as the agent left it. Cheap when nothing is parked.
pub(crate) async fn resume(state: &mut DaemonState) {
    let parked = std::mem::take(&mut state.idle_park);
    if parked.cover.is_none() && parked.frozen.is_empty() {
        return;
    }
    let Some(browser) = state.browser.as_ref() else {
        return;
    };
    let client = browser.client.clone();
    for session in &parked.frozen {
        let _ = send(
            &client,
            "Page.setWebLifecycleState",
            json!({ "state": "active" }),
            Some(session),
        )
        .await;
    }
    for target in &parked.restore {
        let _ = send(
            &client,
            "Target.activateTarget",
            json!({ "targetId": target }),
            None,
        )
        .await;
    }
    if let Some(cover) = &parked.cover {
        close_target(&client, cover).await;
    }
    // The renderer learns it is visible a moment after the tab is activated.
    if let Some(session) = parked
        .restore
        .last()
        .and_then(|target| browser.session_id_for_target(target))
    {
        for _ in 0..20 {
            if visibility(&client, session).await.as_deref() != Some("hidden") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

async fn close_target(client: &CdpClient, target: &str) {
    let _ = send(
        client,
        "Target.closeTarget",
        json!({ "targetId": target }),
        None,
    )
    .await;
}

async fn visibility(client: &CdpClient, session: &str) -> Option<String> {
    send(
        client,
        "Runtime.evaluate",
        json!({ "expression": "document.visibilityState", "returnByValue": true }),
        Some(session),
    )
    .await?
    .pointer("/result/value")?
    .as_str()
    .map(str::to_string)
}

async fn send(
    client: &CdpClient,
    method: &str,
    params: Value,
    session: Option<&str>,
) -> Option<Value> {
    tokio::time::timeout(
        CDP_TIMEOUT,
        client.send_command(method, Some(params), session),
    )
    .await
    .ok()?
    .ok()
}

fn cpu_percent(ticks: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    ticks as f64 / clock_ticks_per_second() / seconds * 100.0
}

#[cfg(unix)]
fn clock_ticks_per_second() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as f64
    } else {
        100.0
    }
}

#[cfg(not(unix))]
fn clock_ticks_per_second() -> f64 {
    100.0
}

/// CPU time the browser and every process below it have used, in clock ticks.
#[cfg(target_os = "linux")]
fn tree_cpu_ticks(root: u32) -> Option<u64> {
    let mut processes = Vec::new();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Some((parent, ticks)) = parse_stat(&stat) {
            processes.push((pid, parent, ticks));
        }
    }
    sum_tree(root, &processes)
}

#[cfg(not(target_os = "linux"))]
fn tree_cpu_ticks(_root: u32) -> Option<u64> {
    None
}

/// `(parent pid, utime + stime)` from a `/proc/<pid>/stat` line.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_stat(stat: &str) -> Option<(u32, u64)> {
    // The command name is in parentheses and may itself hold spaces and parentheses.
    let fields: Vec<&str> = stat
        .get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    let parent = fields.get(1)?.parse().ok()?;
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some((parent, user + system))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sum_tree(root: u32, processes: &[(u32, u32, u64)]) -> Option<u64> {
    let mut total = processes
        .iter()
        .find(|(pid, _, _)| *pid == root)
        .map(|(_, _, ticks)| *ticks)?;
    let mut tree = vec![root];
    let mut next = 0;
    while next < tree.len() {
        let parent = tree[next];
        next += 1;
        for (pid, of, ticks) in processes {
            if *of == parent && !tree.contains(pid) {
                tree.push(*pid);
                total += ticks;
            }
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_is_off_unless_a_positive_delay_is_set() {
        assert_eq!(Config::parse(None, None), None);
        assert_eq!(Config::parse(Some("0"), None), None);
        assert_eq!(Config::parse(Some("soon"), Some("5")), None);
    }

    #[test]
    fn test_config_reads_delay_and_freeze_threshold() {
        let config = Config::parse(Some("120000"), None).unwrap();
        assert_eq!(config.after, Duration::from_secs(120));
        assert_eq!(config.freeze_cpu, DEFAULT_FREEZE_CPU_PERCENT);

        let config = Config::parse(Some(" 60000 "), Some("0")).unwrap();
        assert_eq!(config.after, Duration::from_secs(60));
        assert_eq!(config.freeze_cpu, 0.0);

        let config = Config::parse(Some("60000"), Some("-3")).unwrap();
        assert_eq!(config.freeze_cpu, DEFAULT_FREEZE_CPU_PERCENT);
    }

    #[test]
    fn test_parse_stat_survives_a_command_name_with_spaces_and_parentheses() {
        let stat = "4242 (Web (Content) x) S 17 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 9 0 1 2 3";
        assert_eq!(parse_stat(stat), Some((17, 300)));
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn test_sum_tree_counts_descendants_only() {
        let processes = [
            (10, 1, 5),
            (11, 10, 7),
            (12, 11, 11),
            (20, 1, 1000),
            (21, 20, 1000),
        ];
        assert_eq!(sum_tree(10, &processes), Some(23));
        assert_eq!(sum_tree(99, &processes), None);
    }

    #[test]
    fn test_cpu_percent_is_relative_to_one_core() {
        let per_second = clock_ticks_per_second() as u64;
        let percent = cpu_percent(per_second * 5, Duration::from_secs(10));
        assert!((percent - 50.0).abs() < 0.01);
        assert_eq!(cpu_percent(10, Duration::ZERO), 0.0);
    }
}
