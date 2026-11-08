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

/// Cloud provider detected via the link-local metadata service (IMDS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Yandex,
    None,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CloudProvider::Aws => "aws",
            CloudProvider::Gcp => "gcp",
            CloudProvider::Yandex => "yandex",
            CloudProvider::None => "none",
        };
        f.write_str(s)
    }
}

/// Read-only IMDS probe (Design Doc 0031 §2.1): identify the cloud provider
/// without tokens or credentials. Strict 500ms budget per hop; any error
/// (including "not a cloud") yields `CloudProvider::None`.
pub async fn probe_cloud_provider() -> CloudProvider {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return CloudProvider::None,
    };
    let imds = "http://169.254.169.254";

    // AWS: IMDSv2 token first, IMDSv1 fallback.
    let token = match client
        .put(format!("{imds}/latest/api/token"))
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r.text().await.ok(),
        _ => None,
    };
    let mut aws_req = client.get(format!("{imds}/latest/meta-data/"));
    if let Some(t) = &token {
        aws_req = aws_req.header("X-aws-ec2-metadata-token", t.as_str());
    }
    if let Ok(resp) = aws_req.send().await
        && resp.status().is_success()
    {
        return CloudProvider::Aws;
    }

    // GCP / Yandex share the metadata protocol (Metadata-Flavor header).
    let flavor_ok = client
        .get(format!("{imds}/computeMetadata/v1/"))
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if flavor_ok {
        // Yandex Cloud exposes a vendor section GCP does not have.
        let yandex = client
            .get(format!("{imds}/computeMetadata/v1/instance/vendor/"))
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        return if yandex {
            CloudProvider::Yandex
        } else {
            CloudProvider::Gcp
        };
    }

    CloudProvider::None
}
