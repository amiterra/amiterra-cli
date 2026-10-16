use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub is_private: bool,
    pub is_default: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
    pub pod_cidr: String,
    pub service_cidr: String,
}

// Retrieve host network information for initial bootstrap
pub fn get_network_info() -> NetworkInfo {
    let interfaces = get_local_interfaces();
    let occupied_subnets = get_occupied_subnets();
    
    let (pod_cidr, service_cidr) = find_free_cidrs(&occupied_subnets);
    
    NetworkInfo {
        interfaces,
        pod_cidr,
        service_cidr,
    }
}

// Query outgoing route interface for a target IP via 'ip route get'
pub fn get_route_for_ip(target_ip: &str) -> Option<NetworkInterface> {
    let output = Command::new("ip")
        .args(["route", "get", target_ip])
        .output()
        .ok()?;
        
    let stdout = String::from_utf8_lossy(&output.stdout);
    // output example: 10.0.1.10 dev eth1 src 10.0.1.15 uid 0
    
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    let mut dev = None;
    let mut src = None;
    
    for (i, part) in parts.iter().enumerate() {
        if *part == "dev" && i + 1 < parts.len() {
            dev = Some(parts[i + 1].to_string());
        }
        if *part == "src" && i + 1 < parts.len() {
            src = Some(parts[i + 1].to_string());
        }
    }
    
    if let (Some(name), Some(ip)) = (dev, src) {
        let is_private = is_rfc1918(&ip);
        Some(NetworkInterface {
            name,
            ip,
            is_private,
            is_default: false,
        })
    } else {
        None
    }
}

fn get_local_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    
    // 1. Identify default route interface
    let default_dev = get_default_interface();
    
    // 2. List all IPv4 addresses via 'ip -o -4 addr'
    let output = match Command::new("ip").args(["-o", "-4", "addr"]).output() {
        Ok(out) => out,
        Err(_) => return interfaces,
    };
        
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let name = parts[1].to_string();
            if name == "lo" || name.starts_with("docker") || name.starts_with("cilium") || name.starts_with("flannel") {
                continue;
            }
            
            let cidr = parts[3];
            let ip = cidr.split('/').next().unwrap_or("").to_string();
            
            let is_default = default_dev.as_ref().is_some_and(|d| d == &name);
            let is_private = is_rfc1918(&ip);
            
            interfaces.push(NetworkInterface {
                name,
                ip,
                is_private,
                is_default,
            });
        }
    }
    
    interfaces
}

fn get_default_interface() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
        
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    
    for (i, part) in parts.iter().enumerate() {
        if *part == "dev" && i + 1 < parts.len() {
            return Some(parts[i + 1].to_string());
        }
    }
    None
}

fn get_occupied_subnets() -> Vec<String> {
    let mut subnets = Vec::new();
    let output = match Command::new("ip").args(["-4", "route"]).output() {
        Ok(out) => out,
        Err(_) => return subnets,
    };
        
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() && parts[0] != "default" {
            subnets.push(parts[0].to_string());
        }
    }
    subnets
}

fn find_free_cidrs(occupied: &[String]) -> (String, String) {
    let candidate_blocks = [
        ("10.42.0.0/16", "10.43.0.0/16"),
        ("10.44.0.0/16", "10.45.0.0/16"),
        ("10.46.0.0/16", "10.47.0.0/16"),
        ("172.16.0.0/16", "172.17.0.0/16"),
        ("172.18.0.0/16", "172.19.0.0/16"),
    ];

    for (pod, svc) in candidate_blocks {
        let mut conflicts = false;
        let pod_prefix = pod.split(".0.0/16").next().unwrap_or("");
        let svc_prefix = svc.split(".0.0/16").next().unwrap_or("");
        
        for subnet in occupied {
            if subnet.starts_with(pod_prefix) || subnet.starts_with(svc_prefix) {
                conflicts = true;
                break;
            }
        }
        
        if !conflicts {
            if pod != "10.42.0.0/16" {
                info!("Default K3s CIDRs conflict with host routes. Selected alternative: {}", pod);
            }
            return (pod.to_string(), svc.to_string());
        }
    }
    
    // Fallback if all candidate blocks conflict
    warn!("Could not find completely free CIDR block! Falling back to 10.42.0.0/16");
    ("10.42.0.0/16".to_string(), "10.43.0.0/16".to_string())
}

fn is_rfc1918(ip: &str) -> bool {
    if ip.starts_with("10.") || ip.starts_with("192.168.") {
        return true;
    }
    if ip.starts_with("172.") {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 2
            && let Ok(second) = parts[1].parse::<u8>() {
                return (16..=31).contains(&second);
        }
    }
    false
}
