//! Intercept mode: pause requests, allow modification, then forward.

use nexus_core::models::CapturedRequest;
use parking_lot::Mutex;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::{Notify, oneshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptMode {
    /// Pass all traffic through without pausing.
    Passthrough,
    /// Pause every request — wait for user action.
    InterceptAll,
    /// Pause only requests matching a URL pattern.
    InterceptMatching(String),
}

// ─── Pending item ─────────────────────────────────────────────────────────────

struct PendingRequest {
    request: CapturedRequest,
    /// Oneshot that resolves with the (possibly modified) request, or None to drop.
    reply: oneshot::Sender<Option<CapturedRequest>>,
}

// ─── InterceptHandle ──────────────────────────────────────────────────────────

/// Shared handle accessible from both the proxy handler and the UI/API.
pub struct InterceptHandle {
    mode:    Mutex<InterceptMode>,
    queue:   Mutex<VecDeque<PendingRequest>>,
    notify:  Notify,
}

impl InterceptHandle {
    pub fn new() -> Self {
        Self {
            mode:   Mutex::new(InterceptMode::Passthrough),
            queue:  Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    pub fn set_mode(&self, mode: InterceptMode) {
        *self.mode.lock() = mode;
    }

    pub fn mode(&self) -> InterceptMode {
        self.mode.lock().clone()
    }

    /// Called by the proxy handler. If intercept is enabled, this blocks until
    /// the request is released by the user. Returns `None` if the request was dropped.
    pub async fn maybe_intercept(
        self: &Arc<Self>,
        request: CapturedRequest,
    ) -> Option<CapturedRequest> {
        let should_intercept = match &*self.mode.lock() {
            InterceptMode::Passthrough => false,
            InterceptMode::InterceptAll => true,
            InterceptMode::InterceptMatching(pattern) => request.url.contains(pattern.as_str()),
        };

        if !should_intercept {
            return Some(request);
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut q = self.queue.lock();
            q.push_back(PendingRequest { request, reply: tx });
        }
        self.notify.notify_one();

        rx.await.unwrap_or(None)
    }

    /// Returns the next intercepted request (for UI polling).
    /// Returns `None` if queue is empty.
    pub fn next_pending(&self) -> Option<CapturedRequest> {
        // Peek without consuming — the UI will call forward/drop separately
        self.queue.lock().front().map(|p| p.request.clone())
    }

    pub fn pending_count(&self) -> usize {
        self.queue.lock().len()
    }

    /// Forward the front-of-queue request (optionally with modifications).
    pub fn forward(&self, modified: Option<CapturedRequest>) {
        if let Some(item) = self.queue.lock().pop_front() {
            let _ = item.reply.send(modified.or(Some(item.request)));
        }
    }

    /// Drop the front-of-queue request (do not forward).
    pub fn drop_request(&self) {
        if let Some(item) = self.queue.lock().pop_front() {
            let _ = item.reply.send(None);
        }
    }

    /// Wait until there is at least one pending request in the queue.
    pub async fn wait_for_request(&self) {
        loop {
            if !self.queue.lock().is_empty() {
                return;
            }
            self.notify.notified().await;
        }
    }
}
