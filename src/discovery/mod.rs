pub mod network;
pub mod probe;

pub use network::{
    HostTopology, NetworkInterface, classify_topology, find_collision_free_cidrs,
    generate_tls_sans, get_occupied_subnets, scan_local_interfaces,
};
pub use probe::probe_public_ip;

use serde::{Deserialize, Serialize};

/// Comprehensive report of host networking capabilities and topology.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveryReport {
    pub hostname: String,
    pub interfaces: Vec<NetworkInterface>,
    pub topology: HostTopology,
    pub public_probed_ip: Option<String>,
    pub pod_cidr: String,
    pub service_cidr: String,
    pub cidr_collision_prevented: bool,
    pub tls_sans: Vec<String>,
}

pub struct NetworkDiscovery;

impl NetworkDiscovery {
    /// Executes the full discovery pipeline asynchronously.
    pub async fn run_async() -> DiscoveryReport {
        let hostname = match std::process::Command::new("hostname").output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            Err(_) => "amiterra-node".to_string(),
        };

        let interfaces = scan_local_interfaces();
        let occupied_subnets = get_occupied_subnets();
        let (pod_cidr, service_cidr, cidr_collision_prevented) =
            find_collision_free_cidrs(&occupied_subnets);

        // Run fast outbound probe to determine if behind NAT
        let public_probed_ip = probe_public_ip().await;

        let topology = classify_topology(&interfaces, public_probed_ip.as_deref());

        let node_ip = topology.primary_node_ip();
        // SANs get only node-owned addresses: a NAT gateway's egress IP is
        // not a valid name for this API server (declared = enforced).
        let external_ip = topology.node_owned_external_ip();

        let tls_sans = generate_tls_sans(&hostname, node_ip, external_ip, &[]);

        DiscoveryReport {
            hostname,
            interfaces,
            topology,
            public_probed_ip,
            pod_cidr,
            service_cidr,
            cidr_collision_prevented,
            tls_sans,
        }
    }

    /// Executes the full discovery pipeline synchronously.
    pub fn run() -> DiscoveryReport {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(Self::run_async()))
        } else if let Ok(rt) = tokio::runtime::Runtime::new() {
            rt.block_on(Self::run_async())
        } else {
            let hostname = match std::process::Command::new("hostname").output() {
                Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
                Err(_) => "amiterra-node".to_string(),
            };
            let interfaces = scan_local_interfaces();
            let occupied_subnets = get_occupied_subnets();
            let (pod_cidr, service_cidr, cidr_collision_prevented) =
                find_collision_free_cidrs(&occupied_subnets);
            let topology = classify_topology(&interfaces, None);
            let node_ip = topology.primary_node_ip();
            let external_ip = topology.node_owned_external_ip();
            let tls_sans = generate_tls_sans(&hostname, node_ip, external_ip, &[]);
            DiscoveryReport {
                hostname,
                interfaces,
                topology,
                public_probed_ip: None,
                pod_cidr,
                service_cidr,
                cidr_collision_prevented,
                tls_sans,
            }
        }
    }
}
