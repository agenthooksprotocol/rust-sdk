//! Source-scoped event lineage; unknown ancestors are allowed for subscribers.
use crate::interop::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Default)]
pub struct TaskLineage {
    events: BTreeMap<(String, String), Value>,
}
impl TaskLineage {
    /// Call after canonical envelope validation. Commits only if every known edge is valid.
    pub fn accept(&mut self, event: &Value) -> Result<()> {
        let source = event["source"].as_str().ok_or("missing source")?;
        let id = event["id"].as_str().ok_or("missing event identity")?;
        let key = (source.to_owned(), id.to_owned());
        if let Some(old) = self.events.get(&key) {
            // An intercepted proposal and its effective observation share identity.
            if old["parentEventId"] != event["parentEventId"] || old["type"] != event["type"] {
                return Err("event identity changed lineage".into());
            }
        }
        let mut staged = self.events.clone();
        staged.insert(key, event.clone());
        for ((source, id), event) in &staged {
            let mut seen = BTreeSet::from([id.as_str()]);
            let mut parent = event["parentEventId"].as_str();
            while let Some(p) = parent {
                if !seen.insert(p) {
                    return Err("cyclic event lineage".into());
                }
                parent = staged
                    .get(&(source.clone(), p.to_owned()))
                    .and_then(|e| e["parentEventId"].as_str());
            }
            if event["type"] == "task.change.after" {
                if let Some(before) = event["parentEventId"]
                    .as_str()
                    .and_then(|p| staged.get(&(source.clone(), p.to_owned())))
                {
                    if before["type"] == "task.change.before"
                        && (before["task"]["id"] != event["task"]["id"]
                            || before["task"]["operation"] != event["task"]["operation"])
                    {
                        return Err("task pair identity mismatch".into());
                    }
                }
            }
            if event["type"] == "workspace.change.after" {
                if let Some(before) = event["parentEventId"]
                    .as_str()
                    .and_then(|p| staged.get(&(source.clone(), p.to_owned())))
                {
                    if before["type"] == "workspace.change.before"
                        && before["workspace"]["kind"] != event["workspace"]["kind"]
                    {
                        return Err("workspace pair kind mismatch".into());
                    }
                }
            }
            for kind in ["task", "workspace"] {
                if event["type"] == format!("{kind}.change.after") {
                    if let (Some(prior), Some(change)) = (
                        event[kind]["prior"].as_object(),
                        event[kind]["change"].as_object(),
                    ) {
                        if change.iter().all(|(k, v)| prior.get(k) == Some(v)) {
                            return Err("actual change is a no-op".into());
                        }
                    }
                }
            }
        }
        self.events = staged;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn late_cycle_is_atomic_and_sources_are_independent() {
        let mut l = TaskLineage::default();
        l.accept(&json!({"source":"s","id":"a","parentEventId":"b"}))
            .unwrap();
        assert!(
            l.accept(&json!({"source":"s","id":"b","parentEventId":"a"}))
                .is_err()
        );
        l.accept(&json!({"source":"s","id":"b"})).unwrap();
        l.accept(&json!({"source":"other","id":"b","parentEventId":"a"}))
            .unwrap();
    }
}
