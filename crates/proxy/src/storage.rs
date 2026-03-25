//! In-memory traffic storage with optional persistence.
//! Also provides a broadcast channel for real-time consumers (scanner, UI).

use dashmap::DashMap;
use nexus_core::models::{CapturedRequest, CapturedResponse};
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::types::ProxyEvent;

const BROADCAST_CAP: usize = 4096;

pub struct ProxyStorage {
    requests:  DashMap<Uuid, CapturedRequest>,
    responses: DashMap<Uuid, CapturedResponse>,
    /// Request ordering (for display)
    order:     parking_lot::Mutex<Vec<Uuid>>,
    tx:        broadcast::Sender<ProxyEvent>,
}

impl ProxyStorage {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            requests:  DashMap::new(),
            responses: DashMap::new(),
            order:     parking_lot::Mutex::new(Vec::new()),
            tx,
        }
    }

    /// Subscribe to real-time proxy events.
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.tx.subscribe()
    }

    /// Store a captured request and emit a `RequestCaptured` event.
    pub fn store_request(&self, req: CapturedRequest) {
        let id = req.id;
        let event = ProxyEvent::RequestCaptured(Box::new(req.clone()));
        self.order.lock().push(id);
        self.requests.insert(id, req);
        let _ = self.tx.send(event);
    }

    /// Store a captured response and emit a `ResponseCaptured` event.
    pub fn store_response(&self, req: CapturedRequest, resp: CapturedResponse) {
        let resp_id = resp.id;
        let event = ProxyEvent::ResponseCaptured(
            Box::new(req.clone()),
            Box::new(resp.clone()),
        );
        self.responses.insert(resp_id, resp);
        // Update stored request with response pairing
        let _ = self.tx.send(event);
    }

    pub fn get_request(&self, id: &Uuid) -> Option<CapturedRequest> {
        self.requests.get(id).map(|r| r.clone())
    }

    pub fn get_response_for_request(&self, req_id: &Uuid) -> Option<CapturedResponse> {
        self.responses
            .iter()
            .find(|r| r.request_id == *req_id)
            .map(|r| r.clone())
    }

    pub fn all_requests(&self) -> Vec<CapturedRequest> {
        let order = self.order.lock();
        order
            .iter()
            .filter_map(|id| self.requests.get(id).map(|r| r.clone()))
            .collect()
    }

    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    pub fn clear(&self) {
        self.requests.clear();
        self.responses.clear();
        self.order.lock().clear();
    }

    /// Search requests by URL substring.
    pub fn search(&self, query: &str) -> Vec<CapturedRequest> {
        self.requests
            .iter()
            .filter(|r| r.url.contains(query) || r.host.contains(query))
            .map(|r| r.clone())
            .collect()
    }

    pub fn event_sender(&self) -> broadcast::Sender<ProxyEvent> {
        self.tx.clone()
    }
}
