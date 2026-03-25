//! WebSocket interception stubs.
//! Full bidirectional WebSocket MITM is performed at the handler level —
//! this module provides message capture and event emission helpers.

use nexus_core::models::CapturedRequest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub id:           Uuid,
    pub connection_id: Uuid,
    pub direction:    WsDirection,
    pub opcode:       u8,
    pub payload:      Vec<u8>,
    pub payload_text: Option<String>,
    pub timestamp:    chrono::DateTime<chrono::Utc>,
}

impl WsMessage {
    pub fn new(connection_id: Uuid, direction: WsDirection, opcode: u8, payload: Vec<u8>) -> Self {
        let text = String::from_utf8(payload.clone()).ok();
        Self {
            id:            Uuid::new_v4(),
            connection_id,
            direction,
            opcode,
            payload_text:  text,
            payload,
            timestamp:     chrono::Utc::now(),
        }
    }
}
