//! Best-effort delivery of an already-settled boundary, without decision summaries.
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc, thread};

/// `subscriptions` are matching authorized subscriptions. `called` identifies
/// intercept subscriptions already invoked (not backends). Identifiers stay
/// harness-local and never enter notifications. `prepare` must apply
/// existing content permissions/selections and confirm selected uploads. Dropping
/// join handles deliberately prevents observers from delaying interruption.
pub fn dispatch_observations<P, N>(
    event: Value,
    subscriptions: Vec<Value>,
    called: HashSet<String>,
    prepare: P,
    notify: N,
) where
    P: Fn(Value, &Value) -> Result<Value, String> + Send + Sync + 'static,
    N: Fn(Value) -> Result<(), String> + Send + Sync + 'static,
{
    let prepare = Arc::new(prepare);
    let notify = Arc::new(notify);
    for subscription in subscriptions {
        let id = subscription["id"].as_str().unwrap_or_default();
        if subscription["mode"] != "observe"
            && (subscription["mode"] != "intercept" || called.contains(id))
        {
            continue;
        }
        let (event, prepare, notify) = (event.clone(), prepare.clone(), notify.clone());
        thread::spawn(move || {
            if let Ok(projected) = prepare(event.clone(), &subscription) {
                if ["id", "source", "type"]
                    .iter()
                    .any(|key| projected[key] != event[key])
                {
                    return;
                }
                let _ = notify(
                    json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":projected}}),
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};
    #[test]
    fn remaining_interceptors_receive_filtered_effective_notifications() {
        let (tx, rx) = mpsc::channel();
        let (prepared_tx, prepared_rx) = mpsc::channel();
        dispatch_observations(
            json!({"id":"same","source":"urn:test","type":"tool.before","secret":"effective"}),
            vec![
                json!({"id":"called","mode":"intercept"}),
                json!({"id":"remaining","mode":"intercept"}),
                json!({"id":"explicit","mode":"observe"}),
            ],
            HashSet::from(["called".into()]),
            move |mut event, subscription| {
                prepared_tx
                    .send(subscription["id"].as_str().unwrap().to_owned())
                    .unwrap();
                event.as_object_mut().unwrap().remove("secret");
                Ok(event)
            },
            move |note| {
                tx.send(note).unwrap();
                Ok(())
            },
        );
        let notes: Vec<_> = (0..2)
            .map(|_| rx.recv_timeout(Duration::from_secs(1)).unwrap())
            .collect();
        let ids: HashSet<_> = (0..2)
            .map(|_| prepared_rx.recv_timeout(Duration::from_secs(1)).unwrap())
            .collect();
        assert_eq!(ids, HashSet::from(["remaining".into(), "explicit".into()]));
        for note in notes {
            assert_eq!(note["method"], "hooks/observe");
            assert!(note.get("id").is_none());
            assert_eq!(note["params"].as_object().unwrap().len(), 2);
            assert!(note["params"].get("subscriptionId").is_none());
            assert_eq!(note["params"]["event"]["id"], "same");
            assert!(note["params"]["event"].get("secret").is_none());
        }
    }
}
