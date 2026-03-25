//! HyperProxy Core — full MITM proxy with TLS interception, WebSocket support,
//! intercept mode, traffic storage, and upstream proxy chaining.

pub mod ca;
pub mod handler;
pub mod intercept;
pub mod server;
pub mod storage;
pub mod types;
pub mod upstream;
pub mod ws;

pub use ca::CertificateAuthority;
pub use intercept::{InterceptHandle, InterceptMode};
pub use server::ProxyServer;
pub use storage::ProxyStorage;
pub use types::{ProxyConfig, ProxyEvent};
