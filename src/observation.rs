//! Deferred best-effort delivery of an already-settled boundary, without decision summaries.
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

/// One deferred observation. Creating, dropping, or collecting this value runs
/// no callbacks. The caller owns scheduling; no threads or executor are created.
#[must_use = "observations are not delivered until deliver() is awaited"]
pub struct DeferredObservation<P, N> {
    event: Value,
    subscription: Value,
    prepare: Rc<P>,
    notify: Rc<N>,
}
impl<P, N> DeferredObservation<P, N>
where
    P: Fn(Value, &Value) -> Result<Value, String>,
    N: Fn(Value) -> Result<(), String>,
{
    /// Deliver once when polled by the caller. Preparation and notification use
    /// the legacy synchronous callbacks on that polling thread; adapters must
    /// bound their own I/O. No `Send`, `Sync`, or `'static` captures are required.
    /// Errors and callback panics affect only this observation, never settlement
    /// or sibling observations. Dropping this future before polling does nothing.
    pub async fn deliver(self) -> Result<(), String> {
        catch_unwind(AssertUnwindSafe(|| {
            let projected = (self.prepare)(self.event.clone(), &self.subscription)?;
            if ["id", "source", "type"]
                .iter()
                .any(|key| projected[key] != self.event[key])
            {
                return Err("observation projection changed event identity".into());
            }
            (self.notify)(json!({
                "jsonrpc":"2.0",
                "method":"hooks/observe",
                "params":{"protocolVersion":"draft","event":projected}
            }))
        }))
        .unwrap_or_else(|_| Err("observation callback panicked".into()))
    }
}

/// Collect deferred observations for matching authorized subscriptions.
///
/// `called` identifies intercept subscriptions already invoked (not backends).
/// Explicit observers and remaining uncalled interceptors remain independent.
/// Identifiers stay harness-local and never enter notifications. `prepare` must
/// apply existing content permissions/selections and confirm selected uploads.
///
/// Unlike the former fire-and-forget helper, this function starts no delivery.
/// The caller must explicitly await each desired `DeferredObservation::deliver`
/// after settlement; it may also discard observations. Callback signatures are
/// retained, but their former thread-related bounds are no longer necessary.
#[must_use = "collect or schedule the returned deferred observations explicitly"]
pub fn dispatch_observations<P, N>(
    event: Value,
    subscriptions: Vec<Value>,
    called: HashSet<String>,
    prepare: P,
    notify: N,
) -> Vec<DeferredObservation<P, N>>
where
    P: Fn(Value, &Value) -> Result<Value, String>,
    N: Fn(Value) -> Result<(), String>,
{
    let prepare = Rc::new(prepare);
    let notify = Rc::new(notify);
    subscriptions
        .into_iter()
        .filter(|subscription| {
            let id = subscription["id"].as_str().unwrap_or_default();
            subscription["mode"] == "observe"
                || (subscription["mode"] == "intercept" && !called.contains(id))
        })
        .map(|subscription| DeferredObservation {
            event: event.clone(),
            subscription,
            prepare: Rc::clone(&prepare),
            notify: Rc::clone(&notify),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use std::cell::{Cell, RefCell};

    fn event() -> Value {
        json!({"id":"same","source":"urn:test","type":"tool.before","secret":"effective"})
    }
    #[test]
    fn remaining_interceptors_receive_filtered_effective_notifications_lazily() {
        let prepared = RefCell::new(Vec::new());
        let notes = RefCell::new(Vec::new());
        let observations = dispatch_observations(
            event(),
            vec![
                json!({"id":"called","mode":"intercept"}),
                json!({"id":"remaining","mode":"intercept"}),
                json!({"id":"explicit","mode":"observe"}),
            ],
            HashSet::from(["called".into(), "explicit".into()]),
            |mut event, subscription| {
                prepared.borrow_mut().push(subscription["id"].clone());
                event.as_object_mut().unwrap().remove("secret");
                Ok(event)
            },
            |note| {
                notes.borrow_mut().push(note);
                Ok(())
            },
        );
        assert_eq!(observations.len(), 2);
        assert!(prepared.borrow().is_empty());
        assert!(notes.borrow().is_empty());
        for observation in observations {
            block_on(observation.deliver()).unwrap();
        }
        assert_eq!(
            *prepared.borrow(),
            vec![json!("remaining"), json!("explicit")]
        );
        assert_eq!(notes.borrow().len(), 2);
        for note in notes.borrow().iter() {
            assert_eq!(note["method"], "hooks/observe");
            assert!(note.get("id").is_none());
            assert_eq!(note["params"].as_object().unwrap().len(), 2);
            assert!(note["params"].get("subscriptionId").is_none());
            assert_eq!(note["params"]["event"]["id"], "same");
            assert!(note["params"]["event"].get("secret").is_none());
        }
    }
    #[test]
    fn dropping_collection_or_unpolled_delivery_runs_no_callbacks() {
        let calls = Cell::new(0);
        for deliver in [false, true] {
            let mut observations = dispatch_observations(
                event(),
                vec![json!({"id":"observer","mode":"observe"})],
                HashSet::new(),
                |event, _| {
                    calls.set(calls.get() + 1);
                    Ok(event)
                },
                |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            );
            if deliver {
                drop(observations.pop().unwrap().deliver());
            } else {
                drop(observations);
            }
        }
        assert_eq!(calls.get(), 0);
    }
    #[test]
    fn identity_changes_errors_and_panics_are_isolated_per_observation() {
        let notifications = Cell::new(0);
        let observations = dispatch_observations(
            event(),
            [
                "id",
                "source",
                "type",
                "prepare-error",
                "prepare-panic",
                "notify-error",
                "notify-panic",
                "ok",
            ]
            .map(|id| json!({"id":id,"mode":"observe"}))
            .to_vec(),
            HashSet::new(),
            |mut event, subscription| {
                let id = subscription["id"].as_str().unwrap();
                match id {
                    "id" | "source" | "type" => event[id] = json!("changed"),
                    "prepare-error" => return Err("preparation failed".into()),
                    "prepare-panic" => panic!("preparation panic"),
                    _ => event["delivery"] = json!(id),
                }
                Ok(event)
            },
            |note| {
                notifications.set(notifications.get() + 1);
                match note["params"]["event"]["delivery"].as_str().unwrap() {
                    "notify-error" => Err("notification failed".into()),
                    "notify-panic" => panic!("notification panic"),
                    _ => Ok(()),
                }
            },
        );
        let results: Vec<_> = observations
            .into_iter()
            .map(|observation| block_on(observation.deliver()))
            .collect();
        assert!(results[..7].iter().all(Result::is_err));
        assert!(results[7].is_ok());
        assert_eq!(notifications.get(), 3);
    }
}
