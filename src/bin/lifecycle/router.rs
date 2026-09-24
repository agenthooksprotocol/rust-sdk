//! Exact-ID stdio routing. Discarded frames never consume another attempt.
use super::*;
#[derive(Default)]
struct Routing {
    pending: BTreeMap<String, VecDeque<mpsc::Sender<Reply>>>,
    discarded: BTreeMap<String, u64>,
    error: Option<String>,
}
#[derive(Default)]
pub(super) struct Router {
    state: Mutex<Routing>,
    changed: Condvar,
}
impl Router {
    pub(super) fn register(&self, id: &str) -> Result<mpsc::Receiver<Reply>> {
        let mut state = self.state.lock().unwrap();
        if let Some(error) = &state.error {
            return Err(error.clone().into());
        }
        let (tx, rx) = mpsc::channel();
        state.pending.entry(id.into()).or_default().push_back(tx);
        Ok(rx)
    }
    // The reader validates the canonical response before calling route.
    pub(super) fn route(&self, response: Value) {
        let id = s(&response, "id");
        if id == "unsolicited-observer" {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if let Some(tx) = state.pending.get_mut(id).and_then(VecDeque::pop_front) {
            if state.pending[id].is_empty() {
                state.pending.remove(id);
            }
            let _ = tx.send(Ok(response));
        } else {
            *state.discarded.entry(id.into()).or_default() += 1;
            self.changed.notify_all();
        }
    }
    pub(super) fn fail(&self, error: String) {
        let mut state = self.state.lock().unwrap();
        state.error = Some(error.clone());
        for (_, queue) in std::mem::take(&mut state.pending) {
            for tx in queue {
                let _ = tx.send(Err(error.clone()));
            }
        }
        self.changed.notify_all();
    }
    pub(super) fn discarded(&self, id: &str) -> u64 {
        self.state
            .lock()
            .unwrap()
            .discarded
            .get(id)
            .copied()
            .unwrap_or(0)
    }
    pub(super) fn wait_discarded(&self, id: &str, after: u64) -> Result<()> {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, TIMEOUT, |state| {
                state.error.is_none() && state.discarded.get(id).copied().unwrap_or(0) <= after
            })
            .unwrap();
        if state.discarded.get(id).copied().unwrap_or(0) > after {
            return Ok(());
        }
        Err(state
            .error
            .clone()
            .unwrap_or_else(|| "unsolicited frame drain timeout".into())
            .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(id: &str, text: &str) -> Value {
        json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"draft","effects":[{"type":"message","text":text}]}})
    }
    #[test]
    fn reverse_order_replies_only_complete_their_exact_ids() {
        let router = Router::default();
        let a = router.register("a").unwrap();
        let b = router.register("b").unwrap();
        router.route(response("b", "second request first"));
        assert!(matches!(a.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(
            b.recv_timeout(TIMEOUT).unwrap().unwrap(),
            response("b", "second request first")
        );
        router.route(response("a", "first request last"));
        assert_eq!(
            a.recv_timeout(TIMEOUT).unwrap().unwrap(),
            response("a", "first request last")
        );
    }
    #[test]
    fn unmatched_and_drained_frames_leave_pending_attempt_usable() {
        let router = Arc::new(Router::default());
        let old = router.register("old").unwrap();
        router.route(response("old", "accepted"));
        old.recv_timeout(TIMEOUT).unwrap().unwrap();
        let pending = router.register("pending").unwrap();
        // A real reader-style rendezvous: no sleeps or timing assumptions.
        let reader = router.clone();
        let task = thread::spawn(move || {
            reader.route(response("unknown", "must not satisfy pending"));
            reader.route(response("old", "late duplicate"));
            reader.route(response("unsolicited-observer", "observer"));
        });
        router.wait_discarded("unknown", 0).unwrap();
        router.wait_discarded("old", 0).unwrap();
        task.join().unwrap();
        assert_eq!(router.discarded("unsolicited-observer"), 0);
        assert!(matches!(pending.try_recv(), Err(mpsc::TryRecvError::Empty)));
        router.route(response("pending", "valid"));
        assert_eq!(
            pending.recv_timeout(TIMEOUT).unwrap().unwrap(),
            response("pending", "valid")
        );
    }
    #[test]
    fn attempts_with_same_id_are_fifo_and_failures_wake_waiters() {
        let router = Router::default();
        let first = router.register("retry").unwrap();
        let second = router.register("retry").unwrap();
        router.route(response("retry", "first"));
        router.route(response("retry", "different"));
        assert_eq!(
            first.recv_timeout(TIMEOUT).unwrap().unwrap(),
            response("retry", "first")
        );
        assert_eq!(
            second.recv_timeout(TIMEOUT).unwrap().unwrap(),
            response("retry", "different")
        );
        let waiting = router.register("waiting").unwrap();
        router.fail("malformed output".into());
        assert!(waiting.recv_timeout(TIMEOUT).unwrap().is_err());
        assert!(router.wait_discarded("never", 0).is_err());
    }
}
