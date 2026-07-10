use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NetworkConnection {
    pub transport: String,
    pub state: String,
    pub local_address: String,
    pub peer_address: String,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkSummary {
    pub connections: Vec<NetworkConnection>,
}

impl NetworkSummary {
    pub fn from_log_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read network log {}", path.display()))?;
        let mut connections = BTreeMap::new();

        for line in contents.lines() {
            if let Some(connection) = parse_ss_line(line) {
                connections.insert(
                    (
                        connection.transport.clone(),
                        connection.state.clone(),
                        connection.local_address.clone(),
                        connection.peer_address.clone(),
                        connection.process.clone(),
                    ),
                    connection,
                );
            }
        }

        Ok(Self {
            connections: connections.into_values().collect(),
        })
    }

    pub fn count(&self) -> usize {
        self.connections.len()
    }

    pub fn peer_addresses(&self) -> Vec<String> {
        self.connections
            .iter()
            .map(|connection| connection.peer_address.clone())
            .filter(|address| address != "*" && address != "*:*" && address != "0.0.0.0:*")
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

fn parse_ss_line(line: &str) -> Option<NetworkConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 5 {
        return None;
    }

    let transport = parts[0].to_string();
    let state = parts[1].to_string();
    let local_address = parts[4].to_string();
    let peer_address = parts.get(5).copied().unwrap_or_default().to_string();
    let process = parts.get(6).map(|part| (*part).to_string());

    Some(NetworkConnection {
        transport,
        state,
        local_address,
        peer_address,
        process,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_ss_line;

    #[test]
    fn parses_ss_line() {
        let connection = parse_ss_line(
            "tcp ESTAB 0 0 172.17.0.2:48320 93.184.216.34:443 users:((\"curl\",pid=10,fd=5))",
        )
        .unwrap();

        assert_eq!(connection.transport, "tcp");
        assert_eq!(connection.state, "ESTAB");
        assert_eq!(connection.local_address, "172.17.0.2:48320");
        assert_eq!(connection.peer_address, "93.184.216.34:443");
        assert_eq!(
            connection.process,
            Some("users:((\"curl\",pid=10,fd=5))".to_string())
        );
    }
}
