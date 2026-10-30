use std::time::Duration;
use tracing::{debug, warn};

/// Probes external public egress IP via an outbound HTTPS probe to Amiterra or fallback endpoints.
/// Strictly enforces a 1500ms fail-fast timeout so that air-gapped or firewalled nodes never stall.
pub async fn probe_public_ip() -> Option<String> {
    let endpoints = [
        "https://get.amiterra.io/myip",
        "https://api.ipify.org",
        "https://icanhazip.com",
    ];

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP probe client: {}", e);
            return None;
        }
    };

    for url in endpoints {
        debug!("Probing public IP via {}...", url);
        match client.get(url).send().await {
            Ok(resp) => {
                if resp.status().is_success()
                    && let Ok(text) = resp.text().await
                {
                    let ip = text.trim();
                    // Validate basic IPv4 format
                    if is_valid_ipv4(ip) {
                        debug!("Discovered public IP: {}", ip);
                        return Some(ip.to_string());
                    }
                }
            }
            Err(e) => {
                debug!("Probe endpoint {} unreachable ({})", url, e);
            }
        }
    }

    None
}

fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        if part.parse::<u8>().is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4() {
        assert!(is_valid_ipv4("95.217.142.10"));
        assert!(is_valid_ipv4("1.1.1.1"));
        assert!(!is_valid_ipv4("invalid"));
        assert!(!is_valid_ipv4("999.1.1.1"));
        assert!(!is_valid_ipv4("1.1.1"));
    }
}
