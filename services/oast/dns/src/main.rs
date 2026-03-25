//! Ghost Listener DNS Server — OAST DNS callbacks.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use trust_dns_resolver::Name;
use trust_dns_server::{
    authority::Authority,
    authority::Catalog,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
    ServerFuture,
};

#[derive(Clone)]
struct OastDnsHandler {
    interactions: Arc<Mutex<HashMap<String, Vec<OastInteraction>>>>,
}

#[derive(Debug, Clone)]
struct OastInteraction {
    timestamp: chrono::DateTime<chrono::Utc>,
    client_ip: String,
    query: String,
}

impl OastDnsHandler {
    fn new() -> Self {
        Self {
            interactions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn record_interaction(&self, domain: &str, client_ip: &str, query: &str) {
        let mut interactions = self.interactions.lock().await;
        let interaction = OastInteraction {
            timestamp: chrono::Utc::now(),
            client_ip: client_ip.to_string(),
            query: query.to_string(),
        };

        interactions.entry(domain.to_string())
            .or_insert_with(Vec::new)
            .push(interaction);

        println!("📡 OAST DNS: {} queried by {} - {}", domain, client_ip, query);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handler = OastDnsHandler::new();

    // Create wildcard DNS authority
    let mut records = HashMap::new();
    let name = Name::from_ascii("oast.localhost.")?;
    let authority = Box::new(InMemoryAuthority::empty(name, trust_dns_server::authority::ZoneType::Primary, false));

    let mut server = ServerFuture::new(handler);
    server.register_socket(UdpSocket::bind("0.0.0.0:5353").await?);

    println!("👻 Ghost Listener DNS server started on UDP port 5353");
    println!("📡 Listening for OAST callbacks on *.oast.localhost");

    server.block_until_done().await?;
    Ok(())
}
