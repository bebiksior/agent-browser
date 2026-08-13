use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;

use super::cdp::client::CdpClient;
use super::cdp::types::CdpEvent;
use super::security_inspection::{evaluate_in_frame, FrameGraph, FrameWorld};

const DEFAULT_BINDING_NAME: &str = "__agent_browser_postmessage_binding__";
const DEFAULT_WORLD_NAME: &str = "__agent_browser_postmessage_monitor__";
const MAX_HISTORY_EVENTS: usize = 10_000;
const MAX_PARSE_ERRORS: usize = 100;

const MONITOR_SCRIPT_TEMPLATE: &str = r#"(() => {
  const bindingName = __BINDING_NAME__;
  const installKey = '__agent_browser_postmessage_monitor_installed__' + bindingName;
  if (globalThis[installKey]) return false;
  Object.defineProperty(globalThis, installKey, { value: true, configurable: false });
  const maxDepth = __MAX_DEPTH__;
  const maxEntries = __MAX_ENTRIES__;
  const maxStringLength = __MAX_STRING_LENGTH__;

  const truncate = (value) => value.length > maxStringLength
    ? value.slice(0, maxStringLength) + '...[truncated]'
    : value;
  const encode = (value, depth, seen) => {
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') return truncate(value);
    if (typeof value === 'number') {
      return Number.isFinite(value) ? value : { __type: 'number', value: String(value) };
    }
    if (typeof value === 'undefined') return { __type: 'undefined' };
    if (typeof value === 'bigint') return { __type: 'bigint', value: String(value) };
    if (typeof value === 'symbol') return { __type: 'symbol', value: truncate(String(value)) };
    if (typeof value === 'function') return { __type: 'function', value: truncate(String(value)) };
    if (depth >= maxDepth) return { __type: 'max-depth', value: Object.prototype.toString.call(value) };
    if (seen.has(value)) return { __type: 'circular' };
    seen.add(value);
    try {
      if (value instanceof ArrayBuffer) {
        return { __type: 'ArrayBuffer', byteLength: value.byteLength };
      }
      if (ArrayBuffer.isView(value)) {
        return {
          __type: value.constructor ? value.constructor.name : 'ArrayBufferView',
          byteLength: value.byteLength,
          values: Array.from(value.subarray ? value.subarray(0, maxEntries) : []).slice(0, maxEntries),
          truncated: value.length > maxEntries,
        };
      }
      if (value instanceof Date) return { __type: 'Date', value: value.toISOString() };
      if (value instanceof Error) {
        return { __type: value.name || 'Error', message: truncate(value.message || ''), stack: truncate(value.stack || '') };
      }
      if (Array.isArray(value)) {
        return value.slice(0, maxEntries).map((entry) => encode(entry, depth + 1, seen));
      }
      const result = {};
      const keys = Object.keys(value).slice(0, maxEntries);
      for (const key of keys) {
        try {
          result[truncate(key)] = encode(value[key], depth + 1, seen);
        } catch (error) {
          result[truncate(key)] = { __type: 'unreadable', value: truncate(String(error)) };
        }
      }
      if (Object.keys(value).length > maxEntries) result.__truncated = true;
      return result;
    } finally {
      seen.delete(value);
    }
  };

  const describeSource = (source) => {
    if (source === null) return { relation: 'none', up: 0, framePath: [] };
    if (source === window) return { relation: 'self', up: 0, framePath: [] };
    if (window.opener && source === window.opener) return { relation: 'opener', up: 0, framePath: [] };
    if (window.parent !== window && source === window.parent) return { relation: 'parent', up: 1, framePath: [] };
    if (window.top !== window && source === window.top) return { relation: 'top', up: 0, framePath: [] };

    let ancestor = window;
    for (let up = 0; up < 16; up += 1) {
      const queue = [];
      const visited = new Set();
      try {
        for (let index = 0; index < ancestor.length; index += 1) {
          queue.push({ candidate: ancestor[index], path: [index] });
        }
      } catch (_) {}
      while (queue.length > 0 && visited.size < 256) {
        const { candidate, path } = queue.shift();
        if (candidate === source) {
          const relation = up === 0 ? 'descendant' : (path.length === 1 ? 'sibling' : 'relative');
          return { relation, up, framePath: path };
        }
        if (visited.has(candidate) || path.length >= 16) continue;
        visited.add(candidate);
        try {
          for (let index = 0; index < candidate.length; index += 1) {
            queue.push({ candidate: candidate[index], path: path.concat(index) });
          }
        } catch (_) {}
      }
      try {
        if (ancestor.parent === ancestor) break;
        ancestor = ancestor.parent;
      } catch (_) { break; }
    }
    return { relation: 'other', up: 0, framePath: [] };
  };

  window.addEventListener('message', (event) => {
    try {
      const payload = {
        version: 1,
        timestamp: Date.now(),
        receiverUrl: location.href,
        origin: event.origin,
        lastEventId: event.lastEventId || '',
        dataType: Object.prototype.toString.call(event.data),
        data: encode(event.data, 0, new Set()),
        portCount: event.ports ? event.ports.length : 0,
        source: describeSource(event.source),
      };
      globalThis[bindingName](JSON.stringify(payload));
    } catch (_) {}
  }, true);
  return true;
})()"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageMonitorOptions {
    pub binding_name: String,
    pub world_name: String,
    pub max_depth: usize,
    pub max_entries: usize,
    pub max_string_length: usize,
}

impl Default for PostMessageMonitorOptions {
    fn default() -> Self {
        Self {
            binding_name: DEFAULT_BINDING_NAME.to_string(),
            world_name: DEFAULT_WORLD_NAME.to_string(),
            max_depth: 6,
            max_entries: 100,
            max_string_length: 16_384,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageSource {
    pub relation: String,
    #[serde(default)]
    pub up: usize,
    #[serde(default)]
    pub frame_path: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostMessagePayload {
    pub version: u32,
    pub timestamp: f64,
    pub receiver_url: String,
    pub origin: String,
    pub last_event_id: String,
    pub data_type: String,
    pub data: Value,
    pub port_count: usize,
    pub source: PostMessageSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageRecord {
    pub sequence: u64,
    pub receiver_frame_id: Option<String>,
    pub source_frame_id: Option<String>,
    pub receiver_session_id: String,
    pub execution_context_id: i64,
    #[serde(flatten)]
    pub payload: PostMessagePayload,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageHistory {
    pub events: Vec<PostMessageRecord>,
    pub dropped_cdp_events: u64,
    pub parse_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MonitorInstallation {
    pub session_id: String,
    pub script_identifier: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ContextKey {
    session_id: String,
    context_id: i64,
}

pub struct PostMessageMonitor {
    pub options: PostMessageMonitorOptions,
    pub installations: Vec<MonitorInstallation>,
    pub history: PostMessageHistory,
    receiver: broadcast::Receiver<CdpEvent>,
    context_frames: HashMap<ContextKey, String>,
    next_sequence: u64,
    graph: FrameGraph,
}

impl PostMessageMonitor {
    pub async fn sync_graph(
        &mut self,
        client: &CdpClient,
        graph: &FrameGraph,
    ) -> Result<(), String> {
        self.graph = graph.clone();
        let source = monitor_script(&self.options);
        let installed_sessions: BTreeSet<_> = self
            .installations
            .iter()
            .map(|installation| installation.session_id.clone())
            .collect();
        let sessions: BTreeSet<_> = graph
            .frames
            .iter()
            .map(|frame| frame.execution_session_id.clone())
            .collect();
        for session_id in sessions.difference(&installed_sessions) {
            client
                .send_command_no_params("Runtime.enable", Some(session_id))
                .await?;
            client
                .send_command(
                    "Runtime.addBinding",
                    Some(json!({
                        "name": self.options.binding_name,
                        "executionContextName": self.options.world_name,
                    })),
                    Some(session_id),
                )
                .await?;
            let result = client
                .send_command(
                    "Page.addScriptToEvaluateOnNewDocument",
                    Some(json!({
                        "source": source,
                        "worldName": self.options.world_name,
                        "runImmediately": true,
                    })),
                    Some(session_id),
                )
                .await?;
            let identifier = result
                .get("identifier")
                .and_then(Value::as_str)
                .filter(|identifier| !identifier.is_empty())
                .ok_or("Chrome returned no PostMessage monitor script identifier")?;
            self.installations.push(MonitorInstallation {
                session_id: session_id.clone(),
                script_identifier: identifier.to_string(),
            });
        }

        for frame in &graph.frames {
            if self.context_frames.iter().any(|(key, known_frame_id)| {
                key.session_id == frame.execution_session_id && known_frame_id == &frame.frame_id
            }) {
                continue;
            }
            let result = client
                .send_command(
                    "Page.createIsolatedWorld",
                    Some(json!({
                        "frameId": frame.frame_id,
                        "worldName": self.options.world_name,
                        "grantUniveralAccess": false,
                    })),
                    Some(&frame.execution_session_id),
                )
                .await?;
            let context_id = result
                .get("executionContextId")
                .and_then(Value::as_i64)
                .ok_or_else(|| {
                    format!(
                        "Could not create PostMessage monitor world for frame {}",
                        frame.frame_id
                    )
                })?;
            self.context_frames.insert(
                ContextKey {
                    session_id: frame.execution_session_id.clone(),
                    context_id,
                },
                frame.frame_id.clone(),
            );
            let result = client
                .send_command(
                    "Runtime.evaluate",
                    Some(json!({
                        "expression": source,
                        "contextId": context_id,
                        "returnByValue": true,
                    })),
                    Some(&frame.execution_session_id),
                )
                .await?;
            if let Some(details) = result.get("exceptionDetails") {
                return Err(format!(
                    "Could not initialize PostMessage monitor in frame {}: {}",
                    frame.frame_id, details
                ));
            }
        }
        Ok(())
    }

    fn process_event(&mut self, event: CdpEvent) -> Option<PostMessageRecord> {
        let session_id = event.session_id.unwrap_or_default();
        match event.method.as_str() {
            "Runtime.executionContextCreated" => {
                let context = event.params.get("context")?;
                if context.get("name").and_then(Value::as_str)
                    != Some(self.options.world_name.as_str())
                {
                    return None;
                }
                let context_id = context.get("id").and_then(Value::as_i64)?;
                let frame_id = context
                    .get("auxData")
                    .and_then(|aux_data| aux_data.get("frameId"))
                    .and_then(Value::as_str)?;
                self.context_frames.insert(
                    ContextKey {
                        session_id,
                        context_id,
                    },
                    frame_id.to_string(),
                );
                None
            }
            "Runtime.executionContextDestroyed" => {
                if let Some(context_id) = event
                    .params
                    .get("executionContextId")
                    .and_then(Value::as_i64)
                {
                    self.context_frames.remove(&ContextKey {
                        session_id,
                        context_id,
                    });
                }
                None
            }
            "Runtime.executionContextsCleared" => {
                self.context_frames
                    .retain(|key, _| key.session_id != session_id);
                None
            }
            "Runtime.bindingCalled" => {
                if event.params.get("name").and_then(Value::as_str)
                    != Some(self.options.binding_name.as_str())
                {
                    return None;
                }
                let Some(context_id) = event
                    .params
                    .get("executionContextId")
                    .and_then(Value::as_i64)
                else {
                    self.history
                        .parse_errors
                        .push("PostMessage binding event has no executionContextId".to_string());
                    self.cap_parse_errors();
                    return None;
                };
                let Some(raw_payload) = event.params.get("payload").and_then(Value::as_str) else {
                    self.history
                        .parse_errors
                        .push("PostMessage binding event has no payload".to_string());
                    self.cap_parse_errors();
                    return None;
                };
                let payload: PostMessagePayload = match serde_json::from_str(raw_payload) {
                    Ok(payload) => payload,
                    Err(error) => {
                        self.history
                            .parse_errors
                            .push(format!("Invalid PostMessage binding payload: {error}"));
                        self.cap_parse_errors();
                        return None;
                    }
                };
                let receiver_frame_id = self
                    .context_frames
                    .get(&ContextKey {
                        session_id: session_id.clone(),
                        context_id,
                    })
                    .cloned();
                let source_frame_id = receiver_frame_id.as_deref().and_then(|receiver| {
                    resolve_source_frame(&self.graph, receiver, &payload.source)
                });
                let record = PostMessageRecord {
                    sequence: self.next_sequence,
                    receiver_frame_id,
                    source_frame_id,
                    receiver_session_id: session_id,
                    execution_context_id: context_id,
                    payload,
                };
                self.next_sequence += 1;
                self.history.events.push(record.clone());
                if self.history.events.len() > MAX_HISTORY_EVENTS {
                    let excess = self.history.events.len() - MAX_HISTORY_EVENTS;
                    self.history.events.drain(..excess);
                    self.history.dropped_cdp_events += excess as u64;
                }
                Some(record)
            }
            _ => None,
        }
    }

    fn cap_parse_errors(&mut self) {
        if self.history.parse_errors.len() > MAX_PARSE_ERRORS {
            let excess = self.history.parse_errors.len() - MAX_PARSE_ERRORS;
            self.history.parse_errors.drain(..excess);
        }
    }

    pub fn drain_new(&mut self) -> Vec<PostMessageRecord> {
        let mut records = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(event) => {
                    if let Some(record) = self.process_event(event) {
                        records.push(record);
                    }
                }
                Err(broadcast::error::TryRecvError::Lagged(count)) => {
                    self.history.dropped_cdp_events += count;
                }
                Err(broadcast::error::TryRecvError::Empty)
                | Err(broadcast::error::TryRecvError::Closed) => break,
            }
        }
        records
    }

    pub async fn next(&mut self, timeout: Duration) -> Result<Option<PostMessageRecord>, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match tokio::time::timeout(remaining, self.receiver.recv()).await {
                Ok(Ok(event)) => {
                    if let Some(record) = self.process_event(event) {
                        return Ok(Some(record));
                    }
                }
                Ok(Err(broadcast::error::RecvError::Lagged(count))) => {
                    self.history.dropped_cdp_events += count;
                }
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    return Err("CDP event channel closed".to_string())
                }
                Err(_) => return Ok(None),
            }
        }
    }

    pub async fn uninstall(mut self, client: &CdpClient) -> Result<PostMessageHistory, String> {
        self.drain_new();
        let mut first_error = None;
        for installation in &self.installations {
            if let Err(error) = client
                .send_command(
                    "Page.removeScriptToEvaluateOnNewDocument",
                    Some(json!({ "identifier": installation.script_identifier })),
                    Some(&installation.session_id),
                )
                .await
            {
                first_error.get_or_insert(error);
            }
            if let Err(error) = client
                .send_command(
                    "Runtime.removeBinding",
                    Some(json!({ "name": self.options.binding_name })),
                    Some(&installation.session_id),
                )
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(self.history)
    }
}

fn monitor_script(options: &PostMessageMonitorOptions) -> String {
    MONITOR_SCRIPT_TEMPLATE
        .replace(
            "__BINDING_NAME__",
            &serde_json::to_string(&options.binding_name).unwrap_or_else(|_| "null".to_string()),
        )
        .replace("__MAX_DEPTH__", &options.max_depth.to_string())
        .replace("__MAX_ENTRIES__", &options.max_entries.to_string())
        .replace(
            "__MAX_STRING_LENGTH__",
            &options.max_string_length.to_string(),
        )
}

fn validate_options(options: &PostMessageMonitorOptions) -> Result<(), String> {
    if options.binding_name.is_empty() {
        return Err("PostMessage monitor binding name cannot be empty".to_string());
    }
    if options.world_name.is_empty() {
        return Err("PostMessage monitor world name cannot be empty".to_string());
    }
    if options.max_depth == 0 || options.max_entries == 0 || options.max_string_length == 0 {
        return Err("PostMessage monitor serialization limits must be positive".to_string());
    }
    Ok(())
}

pub async fn install_postmessage_monitor(
    client: &CdpClient,
    graph: &FrameGraph,
    mut options: PostMessageMonitorOptions,
) -> Result<PostMessageMonitor, String> {
    if options.binding_name == DEFAULT_BINDING_NAME && options.world_name == DEFAULT_WORLD_NAME {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        options.binding_name = format!("{}{}", DEFAULT_BINDING_NAME, &suffix[..12]);
        options.world_name = format!("{}{}", DEFAULT_WORLD_NAME, &suffix[..12]);
    }
    validate_options(&options)?;
    let source = monitor_script(&options);
    let receiver = client.subscribe();
    let sessions: BTreeSet<_> = graph
        .frames
        .iter()
        .map(|frame| frame.execution_session_id.clone())
        .collect();
    let mut installations = Vec::with_capacity(sessions.len());

    for session_id in sessions {
        client
            .send_command_no_params("Runtime.enable", Some(&session_id))
            .await?;
        client
            .send_command(
                "Runtime.addBinding",
                Some(json!({
                    "name": options.binding_name,
                    "executionContextName": options.world_name,
                })),
                Some(&session_id),
            )
            .await?;
        let result = client
            .send_command(
                "Page.addScriptToEvaluateOnNewDocument",
                Some(json!({
                    "source": source,
                    "worldName": options.world_name,
                    "runImmediately": true,
                })),
                Some(&session_id),
            )
            .await?;
        let identifier = result
            .get("identifier")
            .and_then(Value::as_str)
            .filter(|identifier| !identifier.is_empty())
            .ok_or("Chrome returned no PostMessage monitor script identifier")?;
        installations.push(MonitorInstallation {
            session_id,
            script_identifier: identifier.to_string(),
        });
    }

    let mut context_frames = HashMap::new();
    for frame in &graph.frames {
        let result = client
            .send_command(
                "Page.createIsolatedWorld",
                Some(json!({
                    "frameId": frame.frame_id,
                    "worldName": options.world_name,
                    "grantUniveralAccess": false,
                })),
                Some(&frame.execution_session_id),
            )
            .await?;
        let context_id = result
            .get("executionContextId")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                format!(
                    "Could not create PostMessage monitor world for frame {}",
                    frame.frame_id
                )
            })?;
        context_frames.insert(
            ContextKey {
                session_id: frame.execution_session_id.clone(),
                context_id,
            },
            frame.frame_id.clone(),
        );
        let result = client
            .send_command(
                "Runtime.evaluate",
                Some(json!({
                    "expression": source,
                    "contextId": context_id,
                    "returnByValue": true,
                })),
                Some(&frame.execution_session_id),
            )
            .await?;
        if let Some(details) = result.get("exceptionDetails") {
            return Err(format!(
                "Could not initialize PostMessage monitor in frame {}: {}",
                frame.frame_id, details
            ));
        }
    }

    Ok(PostMessageMonitor {
        options,
        installations,
        history: PostMessageHistory::default(),
        receiver,
        context_frames,
        next_sequence: 1,
        graph: graph.clone(),
    })
}

fn resolve_source_frame(
    graph: &FrameGraph,
    receiver_frame_id: &str,
    source: &PostMessageSource,
) -> Option<String> {
    match source.relation.as_str() {
        "none" | "opener" | "other" => return None,
        "self" => return Some(receiver_frame_id.to_string()),
        "top" => return Some(graph.root_frame_id.clone()),
        _ => {}
    }
    let mut current = receiver_frame_id.to_string();
    for _ in 0..source.up {
        current = graph.get(&current)?.parent_id.clone()?;
    }
    for child_index in &source.frame_path {
        current = graph
            .get(&current)?
            .child_frame_ids
            .get(*child_index)?
            .clone();
    }
    Some(current)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
pub enum PostMessageTarget {
    SelfFrame,
    Parent,
    Top,
    Opener,
    ChildPath(Vec<usize>),
    FrameId(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FrameTraversal {
    pub up: usize,
    pub down: Vec<usize>,
}

pub fn frame_traversal(
    graph: &FrameGraph,
    source_frame_id: &str,
    target_frame_id: &str,
) -> Result<FrameTraversal, String> {
    fn lineage(graph: &FrameGraph, frame_id: &str) -> Result<Vec<String>, String> {
        let mut lineage = graph.ancestor_ids(frame_id)?;
        lineage.push(frame_id.to_string());
        Ok(lineage)
    }

    let source = lineage(graph, source_frame_id)?;
    let target = lineage(graph, target_frame_id)?;
    let common = source
        .iter()
        .zip(&target)
        .take_while(|(left, right)| left == right)
        .count();
    if common == 0 {
        return Err(format!(
            "Frames {source_frame_id} and {target_frame_id} do not share a root"
        ));
    }
    let up = source.len() - common;
    let mut down = Vec::with_capacity(target.len() - common);
    for index in common..target.len() {
        let parent_id = &target[index - 1];
        let child_id = &target[index];
        let parent = graph
            .get(parent_id)
            .ok_or_else(|| format!("Unknown frame ID: {parent_id}"))?;
        let child_index = parent
            .child_frame_ids
            .iter()
            .position(|candidate| candidate == child_id)
            .ok_or_else(|| format!("Frame {child_id} is not a child of {parent_id}"))?;
        down.push(child_index);
    }
    Ok(FrameTraversal { up, down })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageSendResult {
    pub sent: bool,
    pub source_frame_id: String,
    pub target_frame_id: Option<String>,
    pub relation: String,
    pub traversal: Option<FrameTraversal>,
    pub error: Option<String>,
}

fn resolve_target(
    graph: &FrameGraph,
    source_frame_id: &str,
    target: &PostMessageTarget,
) -> Result<(String, Option<String>, Option<FrameTraversal>), String> {
    match target {
        PostMessageTarget::SelfFrame => Ok((
            "self".to_string(),
            Some(source_frame_id.to_string()),
            Some(FrameTraversal {
                up: 0,
                down: Vec::new(),
            }),
        )),
        PostMessageTarget::Parent => {
            let target_id = graph
                .get(source_frame_id)
                .ok_or_else(|| format!("Unknown frame ID: {source_frame_id}"))?
                .parent_id
                .clone()
                .ok_or_else(|| format!("Frame {source_frame_id} has no parent"))?;
            Ok((
                "parent".to_string(),
                Some(target_id),
                Some(FrameTraversal {
                    up: 1,
                    down: Vec::new(),
                }),
            ))
        }
        PostMessageTarget::Top => Ok((
            "top".to_string(),
            Some(graph.root_frame_id.clone()),
            Some(frame_traversal(
                graph,
                source_frame_id,
                &graph.root_frame_id,
            )?),
        )),
        PostMessageTarget::Opener => Ok(("opener".to_string(), None, None)),
        PostMessageTarget::ChildPath(path) => Ok((
            "childPath".to_string(),
            None,
            Some(FrameTraversal {
                up: 0,
                down: path.clone(),
            }),
        )),
        PostMessageTarget::FrameId(target_frame_id) => Ok((
            "frameId".to_string(),
            Some(target_frame_id.clone()),
            Some(frame_traversal(graph, source_frame_id, target_frame_id)?),
        )),
    }
}

pub async fn send_postmessage(
    client: &CdpClient,
    graph: &FrameGraph,
    source_frame_id: &str,
    target: PostMessageTarget,
    message: &Value,
    target_origin: &str,
    world: FrameWorld,
) -> Result<PostMessageSendResult, String> {
    let (relation, target_frame_id, traversal) = resolve_target(graph, source_frame_id, &target)?;
    let traversal_json = serde_json::to_string(&traversal)
        .map_err(|error| format!("Could not serialize frame traversal: {error}"))?;
    let expression = format!(
        r#"(() => {{
  const relation = {relation};
  const traversal = {traversal};
  let targetWindow = window;
  if (relation === 'opener') {{
    targetWindow = window.opener;
  }} else {{
    for (let index = 0; index < traversal.up; index += 1) {{
      if (targetWindow.parent === targetWindow) {{
        return {{ sent: false, error: 'Frame traversal reached the root early' }};
      }}
      targetWindow = targetWindow.parent;
    }}
    for (const childIndex of traversal.down) {{
      if (!Number.isInteger(childIndex) || childIndex < 0 || childIndex >= targetWindow.length) {{
        return {{ sent: false, error: 'Frame traversal child index is unavailable' }};
      }}
      targetWindow = targetWindow[childIndex];
    }}
  }}
  if (!targetWindow) return {{ sent: false, error: 'Target window is unavailable' }};
  targetWindow.postMessage({message}, {target_origin});
  return {{ sent: true, error: null }};
}})()"#,
        relation = json!(relation),
        traversal = traversal_json,
        message = message,
        target_origin = json!(target_origin),
    );
    let evaluation =
        evaluate_in_frame(client, graph, source_frame_id, &expression, world, false).await?;
    let value = evaluation
        .result
        .get("value")
        .cloned()
        .unwrap_or(Value::Null);
    let sent = value.get("sent").and_then(Value::as_bool).unwrap_or(false);
    let error = value
        .get("error")
        .and_then(Value::as_str)
        .map(ToString::to_string);

    Ok(PostMessageSendResult {
        sent,
        source_frame_id: source_frame_id.to_string(),
        target_frame_id,
        relation,
        traversal,
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::super::security_inspection::FrameNode;
    use super::*;

    fn frame(frame_id: &str, parent_id: Option<&str>, children: &[&str]) -> FrameNode {
        FrameNode {
            frame_id: frame_id.to_string(),
            parent_id: parent_id.map(ToString::to_string),
            name: None,
            url: format!("https://{frame_id}.test/"),
            security_origin: format!("https://{frame_id}.test"),
            mime_type: Some("text/html".to_string()),
            unreachable_url: None,
            execution_session_id: "session".to_string(),
            target_id: "target".to_string(),
            oopif_session_id: None,
            execution_contexts: Vec::new(),
            paused_by_dialog: false,
            owner: None,
            child_frame_ids: children.iter().map(|child| child.to_string()).collect(),
        }
    }

    fn graph() -> FrameGraph {
        FrameGraph {
            root_frame_id: "top".to_string(),
            frames: vec![
                frame("top", None, &["left", "right"]),
                frame("left", Some("top"), &["deep"]),
                frame("deep", Some("left"), &[]),
                frame("right", Some("top"), &[]),
            ],
        }
    }

    #[test]
    fn computes_sibling_and_descendant_traversals() {
        assert_eq!(
            frame_traversal(&graph(), "deep", "right").unwrap(),
            FrameTraversal {
                up: 2,
                down: vec![1]
            }
        );
        assert_eq!(
            frame_traversal(&graph(), "top", "deep").unwrap(),
            FrameTraversal {
                up: 0,
                down: vec![0, 0]
            }
        );
    }

    #[test]
    fn parses_binding_payload_without_losing_nested_data() {
        let payload: PostMessagePayload = serde_json::from_value(json!({
            "version": 1,
            "timestamp": 42.0,
            "receiverUrl": "https://receiver.test/",
            "origin": "https://sender.test",
            "lastEventId": "",
            "dataType": "[object Object]",
            "data": { "action": "login", "nested": { "token": "example" } },
            "portCount": 0,
            "source": { "relation": "parent", "framePath": [] }
        }))
        .unwrap();

        assert_eq!(payload.origin, "https://sender.test");
        assert_eq!(payload.data["nested"]["token"], "example");
        assert_eq!(payload.source.relation, "parent");
    }

    #[test]
    fn generated_script_uses_json_encoded_binding_name() {
        let options = PostMessageMonitorOptions {
            binding_name: "binding'\\name".to_string(),
            ..PostMessageMonitorOptions::default()
        };
        let script = monitor_script(&options);
        assert!(script.contains(r#"const bindingName = "binding'\\name";"#));
        assert!(!script.contains("__BINDING_NAME__"));
    }
}
