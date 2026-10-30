use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use tracing::{info, warn};

/// Structured representation of a host network interface.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub cidr: String,
    pub is_private: bool,
    pub is_default: bool,
    pub mtu: u32,
    pub is_storage: bool,
}

/// Classified topology of the host's networking layout.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HostTopology {
    /// Host has only one physical interface with a public IP (e.g. cloud VPS).
    /// Transparent WireGuard eBPF encryption is strictly required for intra-cluster traffic.
    SinglePublicIp {
        interface: String,
        public_ip: String,
    },
    /// Host has separate WAN (internet gateway) and LAN (private RFC 1918 mesh) interfaces.
    MultiNic {
        public_ip: Option<String>,
        public_interface: Option<String>,
        private_ip: String,
        private_interface: String,
        storage_interfaces: Vec<String>,
    },
    /// Host interface has a private IP behind 1:1 NAT (e.g. AWS EC2, GCP).
    PrivateNat {
        private_ip: String,
        public_nat_ip: Option<String>,
        interface: String,
    },
}

impl HostTopology {
    pub fn is_wireguard_required(&self) -> bool {
        matches!(self, HostTopology::SinglePublicIp { .. })
    }

    pub fn primary_node_ip(&self) -> &str {
        match self {
            HostTopology::SinglePublicIp { public_ip, .. } => public_ip,
            HostTopology::MultiNic { private_ip, .. } => private_ip,
            HostTopology::PrivateNat { private_ip, .. } => private_ip,
        }
    }

    pub fn primary_external_ip(&self) -> Option<&str> {
        match self {
            HostTopology::SinglePublicIp { public_ip, .. } => Some(public_ip.as_str()),
            HostTopology::MultiNic { public_ip, .. } => public_ip.as_deref(),
            HostTopology::PrivateNat { public_nat_ip, .. } => public_nat_ip.as_deref(),
        }
    }
}

/// Helper to scan all host network interfaces.
pub fn scan_local_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    let default_iface = get_default_interface();

    #[cfg(unix)]
    {
        // Try 'ip -o -4 addr' first (Linux standard)
        if let Ok(output) = Command::new("ip").args(["-o", "-4", "addr"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let name = parts[1].to_string();
                    if is_ignored_interface(&name) {
                        continue;
                    }
                    let cidr_str = parts[3];
                    let ip = cidr_str.split('/').next().unwrap_or("").to_string();
                    if ip.is_empty() || ip.starts_with("127.") || ip.starts_with("169.254.") {
                        continue;
                    }
                    let is_default = default_iface.as_ref() == Some(&name);
                    let is_private = is_private_ip(&ip);
                    let mtu = read_interface_mtu(&name);
                    let is_storage = is_storage_interface_name(&name);

                    interfaces.push(NetworkInterface {
                        name,
                        ip,
                        cidr: cidr_str.to_string(),
                        is_private,
                        is_default,
                        mtu,
                        is_storage,
                    });
                }
            }
        }
    }

    // Fallback for macOS / testing environments or if 'ip' command is unavailable
    if interfaces.is_empty()
        && let Ok(output) = Command::new("ifconfig").output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_name = String::new();
        for line in stdout.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
                current_name = line.split(':').next().unwrap_or("").to_string();
            } else if line.trim().starts_with("inet ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && !is_ignored_interface(&current_name) {
                    let ip = parts[1].to_string();
                    if ip.is_empty() || ip.starts_with("127.") || ip.starts_with("169.254.") {
                        continue;
                    }
                    let is_private = is_private_ip(&ip);
                    let is_default = current_name == "en0" || current_name == "eth0";
                    let mtu = 1500;
                    interfaces.push(NetworkInterface {
                        name: current_name.clone(),
                        ip,
                        cidr: "32".to_string(),
                        is_private,
                        is_default,
                        mtu,
                        is_storage: false,
                    });
                }
            }
        }
    }

    interfaces
}

/// Identifies the default route network interface via 'ip route show default'.
pub fn get_default_interface() -> Option<String> {
    if let Ok(output) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stdout.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "dev" && i + 1 < parts.len() {
                return Some(parts[i + 1].to_string());
            }
        }
    }
    None
}

/// Classifies host network topology from interfaces and optional public NAT probe result.
pub fn classify_topology(
    interfaces: &[NetworkInterface],
    probed_public_ip: Option<&str>,
) -> HostTopology {
    // 1. Separate into candidate categories
    let non_storage_ifaces: Vec<&NetworkInterface> = interfaces
        .iter()
        .filter(|iface| !iface.is_storage)
        .collect();

    let private_ifaces: Vec<&NetworkInterface> = non_storage_ifaces
        .iter()
        .filter(|i| i.is_private)
        .copied()
        .collect();

    let public_ifaces: Vec<&NetworkInterface> = non_storage_ifaces
        .iter()
        .filter(|i| !i.is_private)
        .copied()
        .collect();

    let storage_names: Vec<String> = interfaces
        .iter()
        .filter(|i| i.is_storage)
        .map(|i| i.name.clone())
        .collect();

    // Topology 1: Single Public IP
    // Host has physical interface(s) with public IP and NO private RFC 1918 interfaces.
    if private_ifaces.is_empty()
        && !public_ifaces.is_empty()
        && let Some(best_pub) = public_ifaces
            .iter()
            .find(|i| i.is_default)
            .or_else(|| public_ifaces.first())
    {
        return HostTopology::SinglePublicIp {
            interface: best_pub.name.clone(),
            public_ip: best_pub.ip.clone(),
        };
    }

    // Topology 2: Multi-NIC Hybrid (WAN + Private LAN)
    if !private_ifaces.is_empty() && !public_ifaces.is_empty() {
        let best_pub = public_ifaces
            .iter()
            .find(|i| i.is_default)
            .or_else(|| public_ifaces.first());

        // For private interface, prefer the one with standard MTU 1500 and not default WAN
        if let Some(best_priv) = private_ifaces
            .iter()
            .find(|i| !i.is_default)
            .or_else(|| private_ifaces.first())
        {
            return HostTopology::MultiNic {
                public_ip: best_pub.map(|i| i.ip.clone()),
                public_interface: best_pub.map(|i| i.name.clone()),
                private_ip: best_priv.ip.clone(),
                private_interface: best_priv.name.clone(),
                storage_interfaces: storage_names,
            };
        }
    }

    // Topology 3: Private NAT
    // All interfaces are private RFC 1918. Default interface is behind NAT.
    let best_priv = private_ifaces
        .iter()
        .find(|i| i.is_default)
        .or_else(|| private_ifaces.first())
        .or_else(|| non_storage_ifaces.first());

    let (priv_ip, priv_iface) = match best_priv {
        Some(i) => (i.ip.clone(), i.name.clone()),
        None => ("127.0.0.1".to_string(), "lo".to_string()),
    };

    HostTopology::PrivateNat {
        private_ip: priv_ip,
        public_nat_ip: probed_public_ip.map(|s| s.to_string()),
        interface: priv_iface,
    }
}

/// Identifies collision-free CIDRs for Pods and Services by scanning active host routes.
pub fn find_collision_free_cidrs(occupied: &[String]) -> (String, String, bool) {
    let candidate_pairs = [
        ("10.42.0.0/16", "10.43.0.0/16"),
        ("10.244.0.0/16", "10.96.0.0/16"),
        ("172.20.0.0/16", "172.21.0.0/16"),
        ("10.100.0.0/16", "10.101.0.0/16"),
    ];

    for (idx, (pod, svc)) in candidate_pairs.iter().enumerate() {
        let mut conflicts = false;
        let pod_prefix = pod.split(".0.0/").next().unwrap_or(pod);
        let svc_prefix = svc.split(".0.0/").next().unwrap_or(svc);

        for subnet in occupied {
            if subnet.starts_with(pod_prefix) || subnet.starts_with(svc_prefix) {
                conflicts = true;
                break;
            }
        }

        if !conflicts {
            let collision_prevented = idx > 0;
            if collision_prevented {
                info!(
                    "Collision detected with default K3s subnets. Auto-selected alternative CIDRs: pod={}, svc={}",
                    pod, svc
                );
            }
            return (pod.to_string(), svc.to_string(), collision_prevented);
        }
    }

    warn!("Could not identify collision-free CIDRs from candidates, falling back to 10.42.0.0/16");
    (
        "10.42.0.0/16".to_string(),
        "10.43.0.0/16".to_string(),
        false,
    )
}

/// Discovers occupied subnets via 'ip -4 route'.
pub fn get_occupied_subnets() -> Vec<String> {
    let mut subnets = Vec::new();
    if let Ok(output) = Command::new("ip").args(["-4", "route"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() && parts[0] != "default" {
                subnets.push(parts[0].to_string());
            }
        }
    }
    subnets
}

/// Generates the canonical list of Subject Alternative Names (TLS SANs) for K3s API server.
pub fn generate_tls_sans(
    hostname: &str,
    node_ip: &str,
    external_ip: Option<&str>,
    custom_domains: &[String],
) -> Vec<String> {
    let mut sans = vec![
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        "kubernetes".to_string(),
        "kubernetes.default".to_string(),
        "kubernetes.default.svc".to_string(),
        "kubernetes.default.svc.cluster.local".to_string(),
    ];

    if !node_ip.is_empty() && !sans.contains(&node_ip.to_string()) {
        sans.push(node_ip.to_string());
    }

    if let Some(ext) = external_ip
        && !ext.is_empty()
        && !sans.contains(&ext.to_string())
    {
        sans.push(ext.to_string());
    }

    if !hostname.is_empty() && !sans.contains(&hostname.to_string()) {
        sans.push(hostname.to_string());
    }

    // Include system FQDN if different from hostname
    if let Ok(output) = Command::new("hostname").arg("-f").output() {
        let fqdn = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !fqdn.is_empty() && fqdn.contains('.') && !sans.contains(&fqdn) {
            sans.push(fqdn);
        }
    }

    for domain in custom_domains {
        let trimmed = domain.trim();
        if !trimmed.is_empty() && !sans.contains(&trimmed.to_string()) {
            sans.push(trimmed.to_string());
        }
    }

    sans
}

/// Checks if an IPv4 address belongs to RFC 1918 private ranges.
pub fn is_rfc1918(ip: &str) -> bool {
    if ip.starts_with("10.") || ip.starts_with("192.168.") {
        return true;
    }
    if ip.starts_with("172.") {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 2
            && let Ok(second) = parts[1].parse::<u8>()
        {
            return (16..=31).contains(&second);
        }
    }
    false
}

/// Checks if an IPv4 address is private/internal, including RFC 1918 and RFC 6598 (Carrier-Grade NAT 100.64.0.0/10).
pub fn is_private_ip(ip: &str) -> bool {
    if is_rfc1918(ip) {
        return true;
    }
    // RFC 6598: Carrier-Grade NAT (CGNAT) 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
    if ip.starts_with("100.") {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 2
            && let Ok(second) = parts[1].parse::<u8>()
        {
            return (64..=127).contains(&second);
        }
    }
    false
}

/// Queries Linux kernel routing table ('ip route get <target>') or BSD route table
/// to determine the precise local egress interface and source IP used to communicate with a target.
pub fn find_route_to_target(target_ip: &str) -> Option<(String, String)> {
    let clean_target = target_ip.trim();
    if clean_target.is_empty() {
        return None;
    }

    #[cfg(unix)]
    {
        // 1. Try Linux 'ip route get <target>'
        if let Ok(output) = Command::new("ip")
            .args(["route", "get", clean_target])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.split_whitespace().collect();
            let mut dev = None;
            let mut src = None;
            for i in 0..parts.len() {
                if parts[i] == "dev" && i + 1 < parts.len() {
                    dev = Some(parts[i + 1].to_string());
                }
                if parts[i] == "src" && i + 1 < parts.len() {
                    src = Some(parts[i + 1].to_string());
                }
            }
            if let (Some(d), Some(s)) = (dev, src) {
                return Some((d, s));
            }
        }

        // 2. Fallback: BSD / macOS 'route -n get <target>'
        if let Ok(output) = Command::new("route")
            .args(["-n", "get", clean_target])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut dev = None;
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("interface:") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        dev = Some(parts[1].to_string());
                        break;
                    }
                }
            }
            if let Some(d) = dev {
                let all_ifaces = scan_local_interfaces();
                if let Some(iface) = all_ifaces.iter().find(|i| i.name == d) {
                    return Some((d, iface.ip.clone()));
                }
            }
        }
    }

    None
}

/// Extracts host or IP from a cluster server URL (e.g. "https://10.20.30.5:6443" -> "10.20.30.5").
pub fn extract_host_from_url(url: &str) -> Option<String> {
    let clean = url.trim();
    let without_scheme = clean
        .strip_prefix("https://")
        .or_else(|| clean.strip_prefix("http://"))
        .unwrap_or(clean);
    let host_part = without_scheme.split(':').next()?.split('/').next()?;
    if !host_part.is_empty() {
        Some(host_part.to_string())
    } else {
        None
    }
}

fn read_interface_mtu(name: &str) -> u32 {
    let path = format!("/sys/class/net/{}/mtu", name);
    if let Ok(content) = fs::read_to_string(path)
        && let Ok(mtu) = content.trim().parse::<u32>()
    {
        return mtu;
    }
    1500
}

fn is_storage_interface_name(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("san") || n.contains("iscsi") || n.contains("ib") || n.contains("storage")
}

pub fn is_ignored_interface(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "lo"
        || n.starts_with("docker")
        || n.starts_with("veth")
        || n.starts_with("cilium")
        || n.starts_with("flannel")
        || n.starts_with("cni")
        || n.starts_with("tailscale")
        || n.starts_with("wg")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("virbr")
        || n.starts_with("vboxnet")
        || n.starts_with("vmnet")
        || n.starts_with("dummy")
        || n.starts_with("kube")
        || n.starts_with("br-")
        || n.starts_with("zt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc1918_detection() {
        assert!(is_rfc1918("10.0.1.15"));
        assert!(is_rfc1918("192.168.1.1"));
        assert!(is_rfc1918("172.16.0.1"));
        assert!(is_rfc1918("172.31.255.255"));
        assert!(!is_rfc1918("172.32.0.1"));
        assert!(!is_rfc1918("95.217.142.10"));
        assert!(!is_rfc1918("1.1.1.1"));
        assert!(!is_rfc1918("127.0.0.1"));
    }

    #[test]
    fn test_classify_single_public_ip() {
        let interfaces = vec![NetworkInterface {
            name: "eth0".to_string(),
            ip: "95.217.142.10".to_string(),
            cidr: "95.217.142.10/26".to_string(),
            is_private: false,
            is_default: true,
            mtu: 1500,
            is_storage: false,
        }];

        let topo = classify_topology(&interfaces, None);
        assert_eq!(
            topo,
            HostTopology::SinglePublicIp {
                interface: "eth0".to_string(),
                public_ip: "95.217.142.10".to_string(),
            }
        );
        assert!(topo.is_wireguard_required());
        assert_eq!(topo.primary_node_ip(), "95.217.142.10");
        assert_eq!(topo.primary_external_ip(), Some("95.217.142.10"));
    }

    #[test]
    fn test_classify_multi_nic_hybrid_with_storage() {
        let interfaces = vec![
            NetworkInterface {
                name: "eth0".to_string(),
                ip: "95.217.142.10".to_string(),
                cidr: "95.217.142.10/26".to_string(),
                is_private: false,
                is_default: true,
                mtu: 1500,
                is_storage: false,
            },
            NetworkInterface {
                name: "eth1".to_string(),
                ip: "10.0.1.15".to_string(),
                cidr: "10.0.1.15/24".to_string(),
                is_private: true,
                is_default: false,
                mtu: 1500,
                is_storage: false,
            },
            NetworkInterface {
                name: "san0".to_string(),
                ip: "192.168.100.5".to_string(),
                cidr: "192.168.100.5/24".to_string(),
                is_private: true,
                is_default: false,
                mtu: 9000,
                is_storage: true,
            },
        ];

        let topo = classify_topology(&interfaces, None);
        assert_eq!(
            topo,
            HostTopology::MultiNic {
                public_ip: Some("95.217.142.10".to_string()),
                public_interface: Some("eth0".to_string()),
                private_ip: "10.0.1.15".to_string(),
                private_interface: "eth1".to_string(),
                storage_interfaces: vec!["san0".to_string()],
            }
        );
        assert!(!topo.is_wireguard_required());
        assert_eq!(topo.primary_node_ip(), "10.0.1.15");
        assert_eq!(topo.primary_external_ip(), Some("95.217.142.10"));
    }

    #[test]
    fn test_classify_multi_nic_with_jumbo_frames_mesh() {
        // High-performance Kafka or database replication network with MTU 9000 on the private mesh
        let interfaces = vec![
            NetworkInterface {
                name: "eth0".to_string(),
                ip: "95.217.142.10".to_string(),
                cidr: "95.217.142.10/26".to_string(),
                is_private: false,
                is_default: true,
                mtu: 1500,
                is_storage: false,
            },
            NetworkInterface {
                name: "eth1".to_string(),
                ip: "10.0.1.15".to_string(),
                cidr: "10.0.1.15/24".to_string(),
                is_private: true,
                is_default: false,
                mtu: 9000, // Jumbo frames for high-throughput Kafka / DB replication!
                is_storage: false,
            },
        ];

        let topo = classify_topology(&interfaces, None);
        assert_eq!(
            topo,
            HostTopology::MultiNic {
                public_ip: Some("95.217.142.10".to_string()),
                public_interface: Some("eth0".to_string()),
                private_ip: "10.0.1.15".to_string(),
                private_interface: "eth1".to_string(),
                storage_interfaces: vec![],
            }
        );
        assert_eq!(topo.primary_node_ip(), "10.0.1.15");
    }

    #[test]
    fn test_collision_free_cidrs_selection() {
        // No conflicts
        let (pod, svc, prevented) = find_collision_free_cidrs(&["192.168.0.0/24".to_string()]);
        assert_eq!(pod, "10.42.0.0/16");
        assert_eq!(svc, "10.43.0.0/16");
        assert!(!prevented);

        // Conflicting default 10.42.0.0
        let (pod, svc, prevented) =
            find_collision_free_cidrs(&["10.42.0.0/24".to_string(), "10.44.0.0/24".to_string()]);
        assert_eq!(pod, "10.244.0.0/16");
        assert_eq!(svc, "10.96.0.0/16");
        assert!(prevented);
    }

    #[test]
    fn test_tls_sans_generation() {
        let sans = generate_tls_sans(
            "node-01",
            "10.0.1.15",
            Some("95.217.142.10"),
            &["cluster.company.io".to_string()],
        );
        assert!(sans.contains(&"127.0.0.1".to_string()));
        assert!(sans.contains(&"10.0.1.15".to_string()));
        assert!(sans.contains(&"95.217.142.10".to_string()));
        assert!(sans.contains(&"node-01".to_string()));
        assert!(sans.contains(&"cluster.company.io".to_string()));
    }

    #[test]
    fn test_private_ip_and_cgnat_rfc6598() {
        // RFC 1918
        assert!(is_private_ip("10.0.1.15"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));

        // RFC 6598: Carrier-Grade NAT (100.64.0.0/10)
        assert!(is_private_ip("100.64.0.1"));
        assert!(is_private_ip("100.100.50.2"));
        assert!(is_private_ip("100.127.255.254"));

        // Outside RFC 6598 (Public routable)
        assert!(!is_private_ip("100.63.255.255"));
        assert!(!is_private_ip("100.128.0.1"));
        assert!(!is_private_ip("95.217.142.10"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn test_ignored_interfaces() {
        // Hypervisor and container interfaces to ignore
        assert!(is_ignored_interface("virbr0"));
        assert!(is_ignored_interface("virbr0-nic"));
        assert!(is_ignored_interface("vboxnet0"));
        assert!(is_ignored_interface("vmnet1"));
        assert!(is_ignored_interface("dummy0"));
        assert!(is_ignored_interface("kube-ipvs0"));
        assert!(is_ignored_interface("br-998822"));
        assert!(is_ignored_interface("docker0"));
        assert!(is_ignored_interface("cilium_host"));
        assert!(is_ignored_interface("wg0"));
        assert!(is_ignored_interface("tailscale0"));

        // Legitimate cluster interfaces that MUST NOT be ignored
        assert!(!is_ignored_interface("eth0"));
        assert!(!is_ignored_interface("enp3s0"));
        assert!(!is_ignored_interface("bond0"));
        assert!(!is_ignored_interface("br0"));
        assert!(!is_ignored_interface("eth0.100"));
        assert!(!is_ignored_interface("ppp0"));
    }

    #[test]
    fn test_classify_cgnat_as_private_nat() {
        let interfaces = vec![NetworkInterface {
            name: "eth0".to_string(),
            ip: "100.64.12.34".to_string(),
            cidr: "100.64.12.34/24".to_string(),
            is_private: true,
            is_default: true,
            mtu: 1500,
            is_storage: false,
        }];

        let topo = classify_topology(&interfaces, Some("198.51.100.1"));
        assert_eq!(
            topo,
            HostTopology::PrivateNat {
                private_ip: "100.64.12.34".to_string(),
                public_nat_ip: Some("198.51.100.1".to_string()),
                interface: "eth0".to_string(),
            }
        );
        assert!(!topo.is_wireguard_required());
        assert_eq!(topo.primary_node_ip(), "100.64.12.34");
        assert_eq!(topo.primary_external_ip(), Some("198.51.100.1"));
    }
}
