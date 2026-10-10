//! Poll-driven upload coordination, independent of any async runtime.
use crate::client::LocalFuture;
use std::{
    collections::BTreeMap,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
#[derive(Clone)]
#[cfg_attr(not(feature = "reqwest"), allow(dead_code))]
pub(crate) struct UploadLimiter(Arc<Mutex<State>>);
#[cfg_attr(not(feature = "reqwest"), allow(dead_code))]
struct State {
    cap: usize,
    active: usize,
    next: usize,
    waiters: BTreeMap<usize, Waker>,
}
impl UploadLimiter {
    pub(crate) fn new(cap: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            cap: cap.max(1),
            active: 0,
            next: 0,
            waiters: BTreeMap::new(),
        })))
    }
    #[cfg_attr(not(feature = "reqwest"), allow(dead_code))]
    pub(crate) fn capacity(&self) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).cap
    }
    #[cfg_attr(not(feature = "reqwest"), allow(dead_code))]
    pub(crate) async fn acquire(&self) -> UploadPermit {
        Acquire {
            limiter: self.clone(),
            id: None,
        }
        .await
    }
}
#[cfg_attr(not(feature = "reqwest"), allow(dead_code))]
struct Acquire {
    limiter: UploadLimiter,
    id: Option<usize>,
}
impl Future for Acquire {
    type Output = UploadPermit;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = this.limiter.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.active < state.cap {
            if let Some(id) = this.id.take() {
                state.waiters.remove(&id);
            }
            state.active += 1;
            Poll::Ready(UploadPermit(this.limiter.clone()))
        } else {
            let id = *this.id.get_or_insert_with(|| {
                let id = state.next;
                state.next += 1;
                id
            });
            state.waiters.insert(id, cx.waker().clone());
            Poll::Pending
        }
    }
}
impl Drop for Acquire {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.limiter
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .waiters
                .remove(&id);
        }
    }
}
#[cfg_attr(not(feature = "reqwest"), allow(dead_code))]
pub(crate) struct UploadPermit(UploadLimiter);
impl Drop for UploadPermit {
    fn drop(&mut self) {
        let waiters = {
            let mut state = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
            state.active -= 1;
            std::mem::take(&mut state.waiters)
        };
        for waker in waiters.into_values() {
            waker.wake();
        }
    }
}
/// Poll at most `cap` jobs at a time; retain input order and cancel on drop.
pub(crate) async fn run_bounded<T: Send>(jobs: Vec<LocalFuture<'_, T>>, cap: usize) -> Vec<T> {
    let len = jobs.len();
    let mut pending = jobs.into_iter().enumerate();
    let mut active = Vec::new();
    let mut results: Vec<Option<T>> = (0..len).map(|_| None).collect();
    poll_fn(move |cx| {
        loop {
            while active.len() < cap.max(1) {
                match pending.next() {
                    Some(job) => active.push(job),
                    None => break,
                }
            }
            let mut completed = false;
            let mut i = 0;
            while i < active.len() {
                if let Poll::Ready(value) = active[i].1.as_mut().poll(cx) {
                    let (index, _) = active.swap_remove(i);
                    results[index] = Some(value);
                    completed = true;
                } else {
                    i += 1;
                }
            }
            if active.is_empty() && pending.len() == 0 {
                return Poll::Ready(
                    results
                        .iter_mut()
                        .map(|v| v.take().expect("completed job"))
                        .collect(),
                );
            }
            if !completed {
                return Poll::Pending;
            }
        }
    })
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_polling_preserves_order_and_cancellation_releases_permits() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        futures::executor::block_on(async {
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let limiter = UploadLimiter::new(3);
            let jobs: Vec<LocalFuture<'_, usize>> = (0usize..12)
                .map(|i| {
                    let active = active.clone();
                    let peak = peak.clone();
                    let limiter = limiter.clone();
                    Box::pin(async move {
                        let _permit = limiter.acquire().await;
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        let mut polls = 0;
                        poll_fn(|cx| {
                            polls += 1;
                            if polls <= 12 - i {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            } else {
                                Poll::Ready(())
                            }
                        })
                        .await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        i
                    }) as LocalFuture<'_, usize>
                })
                .collect();
            assert_eq!(run_bounded(jobs, 8).await, (0..12).collect::<Vec<_>>());
            assert_eq!(peak.load(Ordering::SeqCst), 3);
            let jobs: Vec<LocalFuture<'_, ()>> = (0..3)
                .map(|_| {
                    let limiter = limiter.clone();
                    Box::pin(async move {
                        let _permit = limiter.acquire().await;
                        std::future::pending::<()>().await
                    }) as LocalFuture<'_, ()>
                })
                .collect();
            let mut running = Box::pin(run_bounded(jobs, 3));
            assert!(futures::poll!(running.as_mut()).is_pending());
            drop(running);
            assert_eq!(limiter.0.lock().unwrap().active, 0);
        });
    }

    #[test]
    fn ordered_and_shared_capacity() {
        futures::executor::block_on(async {
            let limiter = UploadLimiter::new(12);
            let mut permits = Vec::new();
            for _ in 0..12 {
                permits.push(limiter.acquire().await);
            }
            let clone = limiter.clone();
            let mut waiting = Box::pin(clone.acquire());
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            permits.pop();
            let permit = waiting.await;
            drop(permit);
            drop(permits);
            let jobs: Vec<LocalFuture<'_, usize>> = (0usize..12)
                .map(|i| Box::pin(async move { i }) as LocalFuture<'_, usize>)
                .collect();
            assert_eq!(run_bounded(jobs, 3).await, (0..12).collect::<Vec<_>>());
        });
    }
}
