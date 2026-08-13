use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::cdp::client::{CdpClient, ExecutionContextInfo};

const DEFAULT_ISOLATED_WORLD_NAME: &str = "__agent_browser_security_inspection__";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FrameOwner {
    pub node_id: Option<i64>,
    pub backend_node_id: Option<i64>,
    pub tag_name: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub sandbox: Option<Vec<String>>,
    pub credentialless: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FrameNode {
    pub frame_id: String,
    pub parent_id: Option<String>,
    pub name: Option<String>,
    pub url: String,
    pub security_origin: String,
    pub mime_type: Option<String>,
    pub unreachable_url: Option<String>,
    pub execution_session_id: String,
    pub target_id: String,
    pub oopif_session_id: Option<String>,
    pub execution_contexts: Vec<ExecutionContextInfo>,
    pub paused_by_dialog: bool,
    pub owner: Option<FrameOwner>,
    pub child_frame_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FrameGraph {
    pub root_frame_id: String,
    pub frames: Vec<FrameNode>,
}

impl FrameGraph {
    pub fn get(&self, frame_id: &str) -> Option<&FrameNode> {
        self.frames.iter().find(|frame| frame.frame_id == frame_id)
    }

    pub fn ancestor_ids(&self, frame_id: &str) -> Result<Vec<String>, String> {
        let mut ancestors = Vec::new();
        let mut current = self
            .get(frame_id)
            .ok_or_else(|| format!("Unknown frame ID: {frame_id}"))?;
        let mut visited = HashSet::new();

        while let Some(parent_id) = current.parent_id.as_deref() {
            if !visited.insert(parent_id.to_string()) {
                return Err(format!("Cycle in frame graph at frame {parent_id}"));
            }
            ancestors.push(parent_id.to_string());
            current = self
                .get(parent_id)
                .ok_or_else(|| format!("Frame {frame_id} has unknown parent {parent_id}"))?;
        }
        ancestors.reverse();
        Ok(ancestors)
    }

    pub fn descendant_ids(&self, frame_id: &str) -> Result<Vec<String>, String> {
        let frame = self
            .get(frame_id)
            .ok_or_else(|| format!("Unknown frame ID: {frame_id}"))?;
        let mut descendants = Vec::new();
        let mut queue: VecDeque<String> = frame.child_frame_ids.iter().cloned().collect();
        let mut visited = HashSet::new();

        while let Some(child_id) = queue.pop_front() {
            if !visited.insert(child_id.clone()) {
                return Err(format!("Cycle in frame graph at frame {child_id}"));
            }
            let child = self
                .get(&child_id)
                .ok_or_else(|| format!("Frame {frame_id} has unknown descendant {child_id}"))?;
            descendants.push(child_id);
            queue.extend(child.child_frame_ids.iter().cloned());
        }
        Ok(descendants)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FrameInspection {
    pub frame: FrameNode,
    pub ancestor_frame_ids: Vec<String>,
    pub descendant_frame_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum FrameWorld {
    Main,
    Isolated {
        name: Option<String>,
        grant_universal_access: bool,
    },
}

impl Default for FrameWorld {
    fn default() -> Self {
        Self::Isolated {
            name: None,
            grant_universal_access: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FrameEvaluation {
    pub frame_id: String,
    pub session_id: String,
    pub context_id: Option<i64>,
    pub world: FrameWorld,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TargetNode {
    pub target_id: String,
    pub target_type: String,
    pub title: String,
    pub url: String,
    pub attached: Option<bool>,
    pub browser_context_id: Option<String>,
    pub opener_id: Option<String>,
    pub opener_frame_id: Option<String>,
    pub parent_frame_id: Option<String>,
    pub can_access_opener: Option<bool>,
    pub subtype: Option<String>,
    pub child_target_ids: Vec<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TargetGraph {
    pub root_target_ids: Vec<String>,
    pub targets: Vec<TargetNode>,
}

impl TargetGraph {
    pub fn get(&self, target_id: &str) -> Option<&TargetNode> {
        self.targets
            .iter()
            .find(|target| target.target_id == target_id)
    }
}

#[derive(Debug, Clone)]
struct RawFrame {
    frame_id: String,
    parent_id: Option<String>,
    name: Option<String>,
    url: String,
    security_origin: String,
    mime_type: Option<String>,
    unreachable_url: Option<String>,
    execution_session_id: String,
    oopif_session_id: Option<String>,
    child_frame_ids: Vec<String>,
}

fn optional_nonempty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn merge_frame_tree(
    tree: &Value,
    inherited_session_id: &str,
    iframe_sessions: &HashMap<String, String>,
    frames: &mut HashMap<String, RawFrame>,
) {
    let Some(frame) = tree.get("frame") else {
        return;
    };
    let Some(frame_id) = frame.get("id").and_then(Value::as_str) else {
        return;
    };
    let oopif_session_id = iframe_sessions.get(frame_id).cloned();
    let execution_session_id = oopif_session_id
        .clone()
        .unwrap_or_else(|| inherited_session_id.to_string());
    let child_frame_ids: Vec<String> = tree
        .get("childFrames")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|child| {
            child
                .get("frame")
                .and_then(|frame| frame.get("id"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .collect();
    let incoming = RawFrame {
        frame_id: frame_id.to_string(),
        parent_id: optional_nonempty_string(frame.get("parentId")),
        name: optional_nonempty_string(frame.get("name")),
        url: frame
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        security_origin: frame
            .get("securityOrigin")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        mime_type: optional_nonempty_string(frame.get("mimeType")),
        unreachable_url: optional_nonempty_string(frame.get("unreachableUrl")),
        execution_session_id: execution_session_id.clone(),
        oopif_session_id,
        child_frame_ids,
    };

    frames
        .entry(frame_id.to_string())
        .and_modify(|existing| {
            if incoming.parent_id.is_some() {
                existing.parent_id.clone_from(&incoming.parent_id);
            }
            if incoming.name.is_some() {
                existing.name.clone_from(&incoming.name);
            }
            if !incoming.url.is_empty() {
                existing.url.clone_from(&incoming.url);
            }
            if !incoming.security_origin.is_empty() {
                existing
                    .security_origin
                    .clone_from(&incoming.security_origin);
            }
            if incoming.mime_type.is_some() {
                existing.mime_type.clone_from(&incoming.mime_type);
            }
            if incoming.unreachable_url.is_some() {
                existing
                    .unreachable_url
                    .clone_from(&incoming.unreachable_url);
            }
            if incoming.oopif_session_id.is_some() {
                existing
                    .execution_session_id
                    .clone_from(&incoming.execution_session_id);
                existing
                    .oopif_session_id
                    .clone_from(&incoming.oopif_session_id);
            }
            if !incoming.child_frame_ids.is_empty() {
                existing
                    .child_frame_ids
                    .clone_from(&incoming.child_frame_ids);
            }
        })
        .or_insert(incoming);

    if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
        for child in children {
            merge_frame_tree(child, &execution_session_id, iframe_sessions, frames);
        }
    }
}

fn frame_reaches_root(
    frame_id: &str,
    root_frame_id: &str,
    frames: &HashMap<String, RawFrame>,
) -> bool {
    let mut current = frame_id;
    let mut visited = HashSet::new();
    loop {
        if current == root_frame_id {
            return true;
        }
        if !visited.insert(current.to_string()) {
            return false;
        }
        let Some(parent_id) = frames
            .get(current)
            .and_then(|frame| frame.parent_id.as_deref())
        else {
            return false;
        };
        current = parent_id;
    }
}

fn ordered_reachable_frame_ids(
    root_frame_id: &str,
    frames: &HashMap<String, RawFrame>,
) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut queue = VecDeque::from([root_frame_id.to_string()]);
    let mut visited = HashSet::new();
    while let Some(frame_id) = queue.pop_front() {
        if !visited.insert(frame_id.clone()) {
            continue;
        }
        let Some(frame) = frames.get(&frame_id) else {
            continue;
        };
        ordered.push(frame_id);
        queue.extend(frame.child_frame_ids.iter().cloned());
    }

    let mut unlinked: Vec<_> = frames
        .keys()
        .filter(|frame_id| {
            !visited.contains(*frame_id) && frame_reaches_root(frame_id, root_frame_id, frames)
        })
        .cloned()
        .collect();
    unlinked.sort_unstable();
    ordered.extend(unlinked);
    ordered
}

fn parse_attributes(attributes: &[Value]) -> BTreeMap<String, String> {
    attributes
        .chunks_exact(2)
        .filter_map(|pair| {
            Some((
                pair.first()?.as_str()?.to_ascii_lowercase(),
                pair.get(1)?.as_str()?.to_string(),
            ))
        })
        .collect()
}

async fn inspect_frame_owner(
    client: &CdpClient,
    frame_id: &str,
    parent_session_id: &str,
) -> Result<FrameOwner, String> {
    let owner = client
        .send_command(
            "DOM.getFrameOwner",
            Some(json!({ "frameId": frame_id })),
            Some(parent_session_id),
        )
        .await?;
    let node_id = owner.get("nodeId").and_then(Value::as_i64);
    let backend_node_id = owner.get("backendNodeId").and_then(Value::as_i64);
    let mut params = serde_json::Map::new();
    if let Some(node_id) = node_id {
        params.insert("nodeId".to_string(), json!(node_id));
    } else if let Some(backend_node_id) = backend_node_id {
        params.insert("backendNodeId".to_string(), json!(backend_node_id));
    } else {
        return Ok(FrameOwner {
            node_id,
            backend_node_id,
            tag_name: None,
            attributes: BTreeMap::new(),
            sandbox: None,
            credentialless: false,
        });
    }
    params.insert("depth".to_string(), json!(0));
    params.insert("pierce".to_string(), json!(true));
    let described = client
        .send_command(
            "DOM.describeNode",
            Some(Value::Object(params)),
            Some(parent_session_id),
        )
        .await?;
    let node = described.get("node").unwrap_or(&Value::Null);
    let attributes = node
        .get("attributes")
        .and_then(Value::as_array)
        .map(|attributes| parse_attributes(attributes))
        .unwrap_or_default();
    let sandbox = attributes.get("sandbox").map(|value| {
        value
            .split_ascii_whitespace()
            .map(ToString::to_string)
            .collect()
    });

    Ok(FrameOwner {
        node_id,
        backend_node_id,
        tag_name: node
            .get("localName")
            .or_else(|| node.get("nodeName"))
            .and_then(Value::as_str)
            .map(|name| name.to_ascii_lowercase()),
        credentialless: attributes.contains_key("credentialless"),
        attributes,
        sandbox,
    })
}

pub async fn collect_frame_graph(
    client: &CdpClient,
    top_session_id: &str,
    top_target_id: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<FrameGraph, String> {
    let top_tree = client
        .send_command_no_params("Page.getFrameTree", Some(top_session_id))
        .await?;
    let root_frame_id = top_tree
        .get("frameTree")
        .and_then(|tree| tree.get("frame"))
        .and_then(|frame| frame.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| "Could not determine top-level frame ID".to_string())?
        .to_string();
    let mut raw_frames = HashMap::new();
    if let Some(tree) = top_tree.get("frameTree") {
        merge_frame_tree(tree, top_session_id, iframe_sessions, &mut raw_frames);
    }

    let mut oopif_session_ids: Vec<_> = iframe_sessions.values().cloned().collect();
    oopif_session_ids.sort_unstable();
    oopif_session_ids.dedup();
    for session_id in oopif_session_ids {
        let Ok(result) = client
            .send_command_no_params("Page.getFrameTree", Some(&session_id))
            .await
        else {
            continue;
        };
        if let Some(tree) = result.get("frameTree") {
            merge_frame_tree(tree, &session_id, iframe_sessions, &mut raw_frames);
        }
    }

    let ordered_ids = ordered_reachable_frame_ids(&root_frame_id, &raw_frames);
    let active_ids: HashSet<_> = ordered_ids.iter().cloned().collect();
    let mut frames = Vec::with_capacity(ordered_ids.len());
    for frame_id in ordered_ids {
        let raw = raw_frames
            .get(&frame_id)
            .ok_or_else(|| format!("Frame graph lost frame {frame_id}"))?;
        let owner = if let Some(parent_id) = raw.parent_id.as_deref() {
            if let Some(parent) = raw_frames.get(parent_id) {
                inspect_frame_owner(client, &raw.frame_id, &parent.execution_session_id)
                    .await
                    .ok()
            } else {
                None
            }
        } else {
            None
        };
        let execution_contexts = client
            .execution_contexts_for_frame(&raw.execution_session_id, &raw.frame_id)
            .await;
        frames.push(FrameNode {
            frame_id: raw.frame_id.clone(),
            parent_id: raw.parent_id.clone(),
            name: raw.name.clone(),
            url: raw.url.clone(),
            security_origin: raw.security_origin.clone(),
            mime_type: raw.mime_type.clone(),
            unreachable_url: raw.unreachable_url.clone(),
            execution_session_id: raw.execution_session_id.clone(),
            target_id: raw
                .oopif_session_id
                .as_ref()
                .map(|_| raw.frame_id.clone())
                .unwrap_or_else(|| top_target_id.to_string()),
            oopif_session_id: raw.oopif_session_id.clone(),
            execution_contexts,
            paused_by_dialog: false,
            owner,
            child_frame_ids: raw
                .child_frame_ids
                .iter()
                .filter(|child_id| active_ids.contains(*child_id))
                .cloned()
                .collect(),
        });
    }

    Ok(FrameGraph {
        root_frame_id,
        frames,
    })
}

pub async fn inspect_frame(
    client: &CdpClient,
    top_session_id: &str,
    top_target_id: &str,
    iframe_sessions: &HashMap<String, String>,
    frame_id: &str,
) -> Result<FrameInspection, String> {
    let graph = collect_frame_graph(client, top_session_id, top_target_id, iframe_sessions).await?;
    let frame = graph
        .get(frame_id)
        .cloned()
        .ok_or_else(|| format!("Unknown frame ID: {frame_id}"))?;
    Ok(FrameInspection {
        frame,
        ancestor_frame_ids: graph.ancestor_ids(frame_id)?,
        descendant_frame_ids: graph.descendant_ids(frame_id)?,
    })
}

fn evaluation_exception(result: &Value) -> Option<String> {
    let details = result.get("exceptionDetails")?;
    details
        .get("exception")
        .and_then(|exception| exception.get("description"))
        .and_then(Value::as_str)
        .or_else(|| details.get("text").and_then(Value::as_str))
        .map(ToString::to_string)
}

pub async fn evaluate_in_frame(
    client: &CdpClient,
    graph: &FrameGraph,
    frame_id: &str,
    expression: &str,
    world: FrameWorld,
    await_promise: bool,
) -> Result<FrameEvaluation, String> {
    let frame = graph
        .get(frame_id)
        .ok_or_else(|| format!("Unknown frame ID: {frame_id}"))?;
    let mut unique_context_id = None;
    let context_id = match &world {
        FrameWorld::Main => {
            let context = client
                .main_world_context(&frame.execution_session_id, &frame.frame_id)
                .await;
            if context.is_none() && frame.parent_id.is_some() && frame.oopif_session_id.is_none() {
                return Err(format!(
                    "Could not resolve the main-world execution context for frame {}",
                    frame.frame_id
                ));
            }
            if let Some(context) = context {
                unique_context_id = context.unique_id;
                Some(context.id)
            } else {
                None
            }
        }
        FrameWorld::Isolated {
            name,
            grant_universal_access,
        } => {
            let result = client
                .send_command(
                    "Page.createIsolatedWorld",
                    Some(json!({
                        "frameId": frame_id,
                        "worldName": name.as_deref().unwrap_or(DEFAULT_ISOLATED_WORLD_NAME),
                        "grantUniveralAccess": grant_universal_access,
                    })),
                    Some(&frame.execution_session_id),
                )
                .await?;
            Some(
                result
                    .get("executionContextId")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| {
                        format!("Could not create an isolated world for frame {frame_id}")
                    })?,
            )
        }
    };
    let mut params = json!({
        "expression": expression,
        "returnByValue": true,
        "awaitPromise": await_promise,
    });
    if let Some(unique_context_id) = unique_context_id {
        params["uniqueContextId"] = json!(unique_context_id);
    } else if let Some(context_id) = context_id {
        params["contextId"] = json!(context_id);
    }
    let result = client
        .send_command(
            "Runtime.evaluate",
            Some(params),
            Some(&frame.execution_session_id),
        )
        .await?;
    if let Some(error) = evaluation_exception(&result) {
        return Err(format!("Evaluation error in frame {frame_id}: {error}"));
    }

    Ok(FrameEvaluation {
        frame_id: frame_id.to_string(),
        session_id: frame.execution_session_id.clone(),
        context_id,
        world,
        result: result.get("result").cloned().unwrap_or(Value::Null),
    })
}

fn parse_target_graph(result: &Value) -> Result<TargetGraph, String> {
    let infos = result
        .get("targetInfos")
        .and_then(Value::as_array)
        .ok_or_else(|| "Target.getTargets returned no targetInfos".to_string())?;
    let known_ids: HashSet<_> = infos
        .iter()
        .filter_map(|info| info.get("targetId").and_then(Value::as_str))
        .collect();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for info in infos {
        let Some(target_id) = info.get("targetId").and_then(Value::as_str) else {
            continue;
        };
        if let Some(opener_id) = info.get("openerId").and_then(Value::as_str) {
            if known_ids.contains(opener_id) {
                children
                    .entry(opener_id.to_string())
                    .or_default()
                    .push(target_id.to_string());
            }
        }
    }
    for child_ids in children.values_mut() {
        child_ids.sort_unstable();
    }

    let mut targets = Vec::with_capacity(infos.len());
    for info in infos {
        let target_id = info
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| "Target info is missing targetId".to_string())?;
        let mut metadata = info.clone();
        if let Value::Object(fields) = &mut metadata {
            for field in [
                "targetId",
                "type",
                "title",
                "url",
                "attached",
                "browserContextId",
                "openerId",
                "openerFrameId",
                "parentFrameId",
                "canAccessOpener",
                "subtype",
            ] {
                fields.remove(field);
            }
        }
        targets.push(TargetNode {
            target_id: target_id.to_string(),
            target_type: info
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            title: info
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            url: info
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            attached: info.get("attached").and_then(Value::as_bool),
            browser_context_id: optional_nonempty_string(info.get("browserContextId")),
            opener_id: optional_nonempty_string(info.get("openerId")),
            opener_frame_id: optional_nonempty_string(info.get("openerFrameId")),
            parent_frame_id: optional_nonempty_string(info.get("parentFrameId")),
            can_access_opener: info.get("canAccessOpener").and_then(Value::as_bool),
            subtype: optional_nonempty_string(info.get("subtype")),
            child_target_ids: children.remove(target_id).unwrap_or_default(),
            metadata,
        });
    }
    targets.sort_unstable_by(|left, right| left.target_id.cmp(&right.target_id));
    let mut root_target_ids: Vec<_> = targets
        .iter()
        .filter(|target| {
            target
                .opener_id
                .as_deref()
                .is_none_or(|opener_id| !known_ids.contains(opener_id))
        })
        .map(|target| target.target_id.clone())
        .collect();
    root_target_ids.sort_unstable();

    Ok(TargetGraph {
        root_target_ids,
        targets,
    })
}

pub async fn collect_target_graph(client: &CdpClient) -> Result<TargetGraph, String> {
    let result = client
        .send_command_no_params("Target.getTargets", None)
        .await?;
    parse_target_graph(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_oopif_tree_and_preserves_parent_session() {
        let top = json!({
            "frame": {
                "id": "top",
                "url": "https://top.test/",
                "securityOrigin": "https://top.test"
            },
            "childFrames": [{
                "frame": {
                    "id": "oopif",
                    "parentId": "top",
                    "url": "https://child.test/",
                    "securityOrigin": "https://child.test"
                }
            }]
        });
        let oopif = json!({
            "frame": {
                "id": "oopif",
                "url": "https://child.test/",
                "securityOrigin": "https://child.test"
            },
            "childFrames": [{
                "frame": {
                    "id": "grandchild",
                    "parentId": "oopif",
                    "url": "about:blank",
                    "securityOrigin": "https://child.test"
                }
            }]
        });
        let sessions = HashMap::from([("oopif".to_string(), "oopif-session".to_string())]);
        let mut frames = HashMap::new();
        merge_frame_tree(&top, "top-session", &sessions, &mut frames);
        merge_frame_tree(&oopif, "oopif-session", &sessions, &mut frames);

        assert_eq!(frames["oopif"].parent_id.as_deref(), Some("top"));
        assert_eq!(frames["oopif"].execution_session_id, "oopif-session");
        assert_eq!(frames["grandchild"].execution_session_id, "oopif-session");
        assert_eq!(frames["oopif"].child_frame_ids, ["grandchild"]);
    }

    #[test]
    fn parses_boolean_and_tokenized_owner_attributes() {
        let attributes = parse_attributes(&[
            json!("src"),
            json!("https://child.test/"),
            json!("sandbox"),
            json!("allow-scripts allow-forms"),
            json!("credentialless"),
            json!(""),
        ]);
        let sandbox: Vec<_> = attributes["sandbox"].split_ascii_whitespace().collect();
        assert_eq!(sandbox, ["allow-scripts", "allow-forms"]);
        assert!(attributes.contains_key("credentialless"));
    }

    #[test]
    fn target_graph_preserves_opener_and_browser_context_metadata() {
        let graph = parse_target_graph(&json!({
            "targetInfos": [
                {
                    "targetId": "popup",
                    "type": "page",
                    "title": "Popup",
                    "url": "https://popup.test/",
                    "attached": true,
                    "openerId": "main",
                    "openerFrameId": "frame-1",
                    "canAccessOpener": false,
                    "browserContextId": "context-1"
                },
                {
                    "targetId": "main",
                    "type": "page",
                    "title": "Main",
                    "url": "https://main.test/",
                    "attached": true
                }
            ]
        }))
        .unwrap();

        assert_eq!(graph.root_target_ids, ["main"]);
        assert_eq!(graph.get("main").unwrap().child_target_ids, ["popup"]);
        let popup = graph.get("popup").unwrap();
        assert_eq!(popup.opener_frame_id.as_deref(), Some("frame-1"));
        assert_eq!(popup.browser_context_id.as_deref(), Some("context-1"));
        assert_eq!(popup.can_access_opener, Some(false));
    }
}
