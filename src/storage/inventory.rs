//! Read-only storage inventory probe.
//!
//! Prefers `lsblk --json` (util-linux). Missing tooling degrades to an empty
//! inventory with `probe_ok=false` so classification still emits guidance.
//!
//! Invariants:
//! - Devices are **unique by name** (RAID MD nodes appear under every member).
//! - Sizes are parsed as **bytes** (`lsblk -b`).
//! - Probe is read-only: no writes, no `--force`, no RAID/LVM mutation.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Command;

/// A block device as reported by util-linux `lsblk --json`.
///
/// Schema notes (util-linux ≥ 2.37):
/// - `type` (not `kind`): disk | part | raid1 | md | loop | rom | …
/// - `mountpoints`: **array** of mount strings (`["/"]`, `[]`, `["[SWAP]"]`)
///   (legacy `mountpoint` singular string also accepted)
/// - `size`: number of bytes when `-b`, human string otherwise
/// - optional columns (`fstype`, `rota`, `model`, `pkname`, `fsused`, `avail`)
///   appear only when requested via `-o`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BlockDevice {
    pub name: String,
    #[serde(default, rename = "type", alias = "kind")]
    pub kind: String,
    /// Parsed device size in bytes (`size` number or `"476.9G"`).
    #[serde(default, rename = "size", deserialize_with = "de_size_bytes")]
    pub size_bytes: Option<u64>,
    /// Display form of `size` (kept for diagnostics).
    #[serde(default, skip_deserializing)]
    pub size: String,
    /// `FSUSED` from lsblk (bytes when `-b`).
    #[serde(default, rename = "fsused", deserialize_with = "de_opt_u64")]
    pub fsused_bytes: Option<u64>,
    /// `AVAIL`/`FSAVAIL` from lsblk (bytes when `-b`).
    #[serde(
        default,
        rename = "avail",
        alias = "fsavail",
        deserialize_with = "de_opt_u64"
    )]
    pub fsavail_bytes: Option<u64>,
    #[serde(default)]
    pub fstype: Option<String>,
    /// All mountpoints (modern `mountpoints: []`).
    #[serde(default, rename = "mountpoints", deserialize_with = "de_mounts")]
    pub mountpoints: Vec<String>,
    /// Legacy single `mountpoint` (util-linux < 2.39). Merged into
    /// [`Self::mountpoints`] after parse — one document may carry both keys,
    /// which must not hard-fail serde as a duplicate field.
    #[serde(default, rename = "mountpoint", skip_serializing)]
    pub legacy_mountpoint: Option<String>,
    #[serde(default)]
    pub rota: Option<bool>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub pkname: Option<String>,
    #[serde(default)]
    pub children: Vec<BlockDevice>,
}

/// Accepts JSON number (bytes) or human size string (`"476.9G"`, `"1022M"`).
fn de_size_bytes<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => parse_size_str(&s),
        Some(other) => {
            return Err(serde::de::Error::custom(format!(
                "invalid size value: {other}"
            )));
        }
    })
}

/// Accepts `mountpoints: ["/"]`, `mountpoints: []`, or legacy `mountpoint: "/"`.
fn de_mounts<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::String(s)) => {
            if s.trim().is_empty() {
                Vec::new()
            } else {
                vec![s]
            }
        }
        Some(serde_json::Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|x| match x {
                serde_json::Value::String(s) if !s.trim().is_empty() => Some(s),
                _ => None,
            })
            .collect(),
        Some(_) => Vec::new(),
    })
}

/// Accepts JSON number or numeric string (lsblk variance).
fn de_opt_u64<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Unexpected};
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.parse::<u64>().map_err(|_| {
                    de::Error::invalid_value(Unexpected::Str(&s), &"unsigned integer")
                })?)
            }
        }
        Some(other) => {
            return Err(de::Error::invalid_value(
                Unexpected::Other(&other.to_string()),
                &"number or numeric string",
            ));
        }
    })
}

/// Parse human sizes like "437G" / "894247137280" best-effort.
pub fn parse_size_str(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(n) = t.parse::<u64>() {
        return Some(n);
    }
    let mut num = String::new();
    let mut unit = String::new();
    for c in t.chars() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
        } else {
            unit.push(c);
        }
    }
    let val: f64 = num.parse().ok()?;
    let mult = match unit.trim().to_ascii_uppercase().as_str() {
        "K" | "KB" | "KIB" => 1024.0,
        "M" | "MB" | "MIB" => 1024.0 * 1024.0,
        "G" | "GB" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    Some((val * mult) as u64)
}

impl BlockDevice {
    /// Primary mountpoint (first real mount), if any.
    pub fn primary_mount(&self) -> Option<&str> {
        self.mountpoints
            .iter()
            .map(|s| s.as_str())
            .find(|s| !s.is_empty() && !s.starts_with('['))
    }

    pub fn has_any_mount(&self) -> bool {
        !self.mountpoints.is_empty()
    }

    pub fn is_swap(&self) -> bool {
        self.mountpoints.iter().any(|m| m.contains("SWAP"))
    }

    /// Whole-disk candidate (not a partition/rom/loop, no mount, no FS).
    pub fn is_unmounted_disk(&self) -> bool {
        let kind = self.kind.as_str();
        let name = self.name.as_str();
        let excluded = name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("zram")
            || name.starts_with("fd")
            || name == "sr0";
        matches!(kind, "disk" | "nvme")
            && !excluded
            && !self.has_any_mount()
            && self.fstype.as_deref().unwrap_or("").is_empty()
            && self.children.is_empty()
    }

    pub fn is_mounted_at_root(&self) -> bool {
        self.mountpoints.iter().any(|m| m == "/")
    }

    pub fn is_rotational(&self) -> bool {
        self.rota.unwrap_or(false)
    }

    /// True for md/dm/array nodes.
    pub fn is_raid_or_md(&self) -> bool {
        let kind = self.kind.as_str();
        kind.starts_with("raid") || kind == "md" || self.name.starts_with("md")
    }

    /// Rough media classification for placement heuristics.
    pub fn media_class(&self) -> &'static str {
        if self.name.starts_with("nvme") {
            return "nvme";
        }
        if self.is_rotational() {
            return "hdd";
        }
        if self.name.starts_with("sd")
            || self.name.starts_with("vd")
            || self.name.starts_with("xvd")
        {
            return "ssd";
        }
        if self.is_raid_or_md() {
            return "raid";
        }
        "unknown"
    }

    /// Flatten device tree (self + children depth-first).
    pub fn walk(&self) -> Vec<&BlockDevice> {
        let mut out = vec![self];
        for c in &self.children {
            out.extend(c.walk());
        }
        out
    }
}

/// Full host storage inventory (Phase A/B artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StorageInventory {
    pub devices: Vec<BlockDevice>,
    /// True when probe tooling ran successfully.
    pub probe_ok: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// A software-RAID (md*) set derived from the device tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RaidSet {
    pub name: String,
    pub level: String,
    pub members: Vec<String>,
    pub size_bytes: Option<u64>,
    pub fstype: Option<String>,
    pub mountpoints: Vec<String>,
}

impl RaidSet {
    pub fn is_swap_mount(&self) -> bool {
        self.mountpoints.iter().any(|m| m.contains("SWAP"))
            || self.fstype.as_deref() == Some("swap")
    }
}

impl StorageInventory {
    /// In-memory inventory for tests / offline classify.
    pub fn from_devices(devices: Vec<BlockDevice>) -> Self {
        let mut devices = devices;
        // Same normalization as probe(): merge legacy `mountpoint` keys.
        normalize_devices(&mut devices);
        Self {
            devices,
            probe_ok: true,
            notes: Vec::new(),
        }
    }

    pub fn walk(&self) -> Vec<&BlockDevice> {
        self.devices.iter().flat_map(|d| d.walk()).collect()
    }

    /// Unique devices by `name` (first occurrence wins). Fixes double-counted `md*`.
    pub fn unique_devices(&self) -> Vec<&BlockDevice> {
        let mut map: BTreeMap<&str, &BlockDevice> = BTreeMap::new();
        for d in self.walk() {
            map.entry(d.name.as_str()).or_insert(d);
        }
        map.into_values().collect()
    }

    /// Disks that look safe to hand to `storage prepare` (no FS, not mounted).
    pub fn free_disks(&self) -> Vec<&BlockDevice> {
        self.unique_devices()
            .into_iter()
            .filter(|d| d.is_unmounted_disk() && (d.kind == "disk" || d.kind == "nvme"))
            .collect()
    }

    pub fn root_devices(&self) -> Vec<&BlockDevice> {
        self.unique_devices()
            .into_iter()
            .filter(|d| d.is_mounted_at_root())
            .collect()
    }

    /// Derive md/RAID sets (unique names + member partition names).
    pub fn raid_sets(&self) -> Vec<RaidSet> {
        // Map: md_name -> member partition names (parents in the tree).
        let mut members: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut nodes: BTreeMap<String, &BlockDevice> = BTreeMap::new();

        fn visit<'a>(
            node: &'a BlockDevice,
            parent: Option<&'a BlockDevice>,
            members: &mut BTreeMap<String, Vec<String>>,
            nodes: &mut BTreeMap<String, &'a BlockDevice>,
        ) {
            if node.is_raid_or_md() {
                nodes.entry(node.name.clone()).or_insert(node);
                if let Some(p) = parent {
                    let entry = members.entry(node.name.clone()).or_default();
                    if !entry.contains(&p.name) {
                        entry.push(p.name.clone());
                    }
                }
            }
            for c in &node.children {
                visit(c, Some(node), members, nodes);
            }
        }

        for d in &self.devices {
            visit(d, None, &mut members, &mut nodes);
        }

        nodes
            .into_iter()
            .map(|(name, dev)| RaidSet {
                level: if dev.kind.starts_with("raid") {
                    dev.kind.clone()
                } else if dev.name.starts_with("md") {
                    "md".into()
                } else {
                    dev.kind.clone()
                },
                members: members.remove(&name).unwrap_or_default(),
                size_bytes: dev.size_bytes,
                fstype: dev.fstype.clone(),
                mountpoints: dev.mountpoints.clone(),
                name,
            })
            .collect()
    }

    /// Probe the live host via `lsblk --json -b`.
    ///
    /// Column sets are tried in order (util-linux versions differ on FSUSED/AVAIL).
    /// Missing/unusable `lsblk` is **not** fatal: empty inventory + `probe_ok=false`
    /// and a diagnostic note.
    pub fn probe() -> Result<Self> {
        const COLUMN_SETS: &[&str] = &[
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,ROTA,MODEL,PKNAME,FSUSED,AVAIL",
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,ROTA,MODEL,PKNAME,FSUSED,FSAVAIL",
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,ROTA,MODEL,PKNAME",
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT",
        ];

        let mut notes = Vec::new();
        let mut saw_lsblk = false;

        for cols in COLUMN_SETS {
            let out = match Command::new("lsblk")
                .args(["--json", "-b", "-o", cols])
                .output()
            {
                Ok(o) => o,
                Err(_) => continue,
            };
            saw_lsblk = true;
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                notes.push(format!("lsblk -o {cols} failed: {}", err.trim()));
                continue;
            }
            match serde_json::from_slice::<LsblkOut>(&out.stdout) {
                Ok(parsed) => {
                    let mut devices = parsed.blockdevices.unwrap_or_default();
                    normalize_devices(&mut devices);
                    if !notes.is_empty() {
                        notes.push(format!("lsblk succeeded with columns: {cols}"));
                    }
                    return Ok(Self {
                        devices,
                        probe_ok: true,
                        notes,
                    });
                }
                Err(e) => {
                    notes.push(format!("lsblk -o {cols} JSON parse failed: {e}"));
                }
            }
        }

        if !saw_lsblk {
            notes.push("lsblk not available on this host; inventory empty".into());
        } else {
            // Last resort: default column set (matches common `lsblk --json -b`).
            if let Ok(out) = Command::new("lsblk").args(["--json", "-b"]).output()
                && out.status.success()
                && let Ok(parsed) = serde_json::from_slice::<LsblkOut>(&out.stdout)
            {
                let mut devices = parsed.blockdevices.unwrap_or_default();
                normalize_devices(&mut devices);
                notes.push("lsblk succeeded with default columns".into());
                return Ok(Self {
                    devices,
                    probe_ok: true,
                    notes,
                });
            }
            notes.push("all lsblk column sets failed; inventory empty".into());
        }
        Ok(Self {
            devices: Vec::new(),
            probe_ok: false,
            notes,
        })
    }
}

/// lsblk JSON root document.
#[derive(Deserialize)]
struct LsblkOut {
    blockdevices: Option<Vec<BlockDevice>>,
}

/// Post-parse normalization: size hook plus merge of the legacy singular
/// `mountpoint` key into `mountpoints` (see [`BlockDevice::legacy_mountpoint`]).
fn normalize_devices(devices: &mut [BlockDevice]) {
    for d in devices.iter_mut() {
        if let Some(m) = d.legacy_mountpoint.take()
            && !m.trim().is_empty()
            && !d.mountpoints.contains(&m)
        {
            d.mountpoints.push(m);
        }
        normalize_devices(&mut d.children);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(name: &str, fstype: Option<&str>, mount: Option<&str>) -> BlockDevice {
        BlockDevice {
            name: name.into(),
            kind: "disk".into(),
            size: "1T".into(),
            fstype: fstype.map(String::from),
            mountpoints: mount.map(|m| vec![m.to_string()]).unwrap_or_default(),
            ..Default::default()
        }
    }

    fn part(name: &str, fstype: Option<&str>, mount: Option<&str>) -> BlockDevice {
        BlockDevice {
            name: name.into(),
            kind: "part".into(),
            size: "500G".into(),
            fstype: fstype.map(String::from),
            mountpoints: mount.map(|m| vec![m.to_string()]).unwrap_or_default(),
            ..Default::default()
        }
    }

    /// Fixture matching a typical dual-NVMe system RAID1 host.
    fn raid_root_inventory() -> StorageInventory {
        let md = BlockDevice {
            name: "md2".into(),
            kind: "raid1".into(),
            size: "437G".into(),
            size_bytes: Some(469_123_456_000),
            fsused_bytes: Some(3_400_000_000),
            fsavail_bytes: Some(411_000_000_000),
            fstype: Some("ext4".into()),
            mountpoints: vec!["/".into()],
            ..Default::default()
        };
        let mut p0 = part("nvme0n1p4", Some("linux_raid_member"), None);
        p0.children = vec![md.clone()];
        let mut p1 = part("nvme1n1p4", Some("linux_raid_member"), None);
        p1.children = vec![md];

        let mut d0 = disk("nvme0n1", None, None);
        d0.children = vec![p0];
        let mut d1 = disk("nvme1n1", None, None);
        d1.children = vec![p1];
        StorageInventory::from_devices(vec![d0, d1])
    }

    #[test]
    fn free_disk_requires_empty_and_unmounted() {
        assert!(disk("nvme2n1", None, None).is_unmounted_disk());
        assert!(!disk("nvme0n1", Some("ext4"), Some("/")).is_unmounted_disk());
        assert!(!part("nvme2n1p1", None, None).is_unmounted_disk());
    }

    #[test]
    fn unique_devices_deduplicates_raid_md() {
        let inv = raid_root_inventory();
        // Raw walk sees md2 twice (under each member).
        assert!(inv.walk().iter().filter(|d| d.name == "md2").count() >= 2);
        let roots = inv.root_devices();
        assert_eq!(roots.len(), 1, "root must be unique md2");
        assert_eq!(roots[0].name, "md2");
    }

    #[test]
    fn raid_sets_group_members() {
        let inv = raid_root_inventory();
        let sets = inv.raid_sets();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].name, "md2");
        assert_eq!(sets[0].level, "raid1");
        assert_eq!(sets[0].members, vec!["nvme0n1p4", "nvme1n1p4"]);
    }

    #[test]
    fn free_disks_filters_system_disks() {
        let mut sys = disk("nvme0n1", None, None);
        sys.children = vec![part("nvme0n1p4", Some("ext4"), Some("/"))];
        let free = disk("nvme2n1", None, None);
        let inv = StorageInventory::from_devices(vec![sys, free]);
        let names: Vec<_> = inv.free_disks().iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["nvme2n1"]);
    }

    #[test]
    fn loop_and_rom_are_not_free_disks() {
        let loopd = BlockDevice {
            name: "loop0".into(),
            kind: "disk".into(),
            ..Default::default()
        };
        assert!(!loopd.is_unmounted_disk());
        let rom = BlockDevice {
            name: "sr0".into(),
            kind: "disk".into(),
            ..Default::default()
        };
        assert!(!rom.is_unmounted_disk());
    }

    #[test]
    fn parse_lsblk_json_shape_with_bytes() {
        let raw = r#"{"blockdevices":[
            {"name":"nvme0n1","type":"disk","size":"894247137280","fstype":null,"mountpoint":null,"children":[
              {"name":"nvme0n1p4","type":"part","size":"469123456000","fstype":"ext4","mountpoint":"/","fsused":"3400000000","avail":"411000000000"}
            ]}
        ]}"#;
        let parsed: LsblkOut = serde_json::from_str(raw).unwrap();
        let mut devices = parsed.blockdevices.unwrap();
        normalize_devices(&mut devices);
        let inv = StorageInventory::from_devices(devices);
        assert_eq!(inv.free_disks().len(), 0);
        let root = inv.root_devices();
        assert_eq!(root[0].name, "nvme0n1p4");
    }

    #[test]
    fn parse_fsavail_alias() {
        let raw = r#"{"blockdevices":[
            {"name":"sda","type":"disk","size":"1000000","fstype":"ext4","mountpoint":"/","fsavail":"12345"}
        ]}"#;
        let parsed: LsblkOut = serde_json::from_str(raw).unwrap();
        let devices = parsed.blockdevices.unwrap();
        assert_eq!(devices[0].fsavail_bytes, Some(12345));
    }

    #[test]
    fn parse_dual_mountpoint_keys_merges() {
        let raw = r#"{"blockdevices":[
            {"name":"sda","type":"disk","fstype":"ext4","mountpoint":"/","mountpoints":["/","/boot"]}
        ]}"#;
        let parsed: LsblkOut = serde_json::from_str(raw).unwrap();
        let mut devices = parsed.blockdevices.unwrap();
        normalize_devices(&mut devices);
        assert_eq!(
            devices[0].mountpoints,
            vec!["/".to_string(), "/boot".to_string()]
        );
        // legacy key is merged away, never duplicated
        assert!(devices[0].legacy_mountpoint.is_none());
    }

    #[test]
    fn media_class_heuristics() {
        let mut n = disk("nvme0n1", None, None);
        n.rota = Some(false);
        assert_eq!(n.media_class(), "nvme");
        let mut h = disk("sda", None, None);
        h.rota = Some(true);
        assert_eq!(h.media_class(), "hdd");
        let mut s = disk("sdb", None, None);
        s.rota = Some(false);
        assert_eq!(s.media_class(), "ssd");
    }

    /// Real util-linux 2.4x output (dual NVMe system RAID1) — schema regression.
    #[test]
    fn parses_real_lsblk_json_dual_nvme_raid() {
        let raw = r#"{
           "blockdevices": [
              {
                 "name": "nvme1n1",
                 "type": "disk",
                 "size": 512110190592,
                 "mountpoints": [],
                 "children": [
                    { "name": "nvme1n1p1", "type": "part", "size": 268435456, "mountpoints": [] },
                    { "name": "nvme1n1p2", "type": "part", "size": 33285996544, "mountpoints": [],
                      "children": [ { "name": "md0", "type": "raid1", "size": 33268170752, "mountpoints": ["[SWAP]"] } ] },
                    { "name": "nvme1n1p3", "type": "part", "size": 1073741824, "mountpoints": [],
                      "children": [ { "name": "md1", "type": "raid1", "size": 1071644672, "mountpoints": ["/boot"] } ] },
                    { "name": "nvme1n1p4", "type": "part", "size": 477479902720, "mountpoints": [],
                      "children": [ { "name": "md2", "type": "raid1", "size": 477344628736, "mountpoints": ["/"] } ] }
                 ]
              },
              {
                 "name": "nvme0n1",
                 "type": "disk",
                 "size": 512110190592,
                 "mountpoints": [],
                 "children": [
                    { "name": "nvme0n1p1", "type": "part", "size": 268435456, "mountpoints": ["/boot/efi"] },
                    { "name": "nvme0n1p2", "type": "part", "size": 33285996544, "mountpoints": [],
                      "children": [ { "name": "md0", "type": "raid1", "size": 33268170752, "mountpoints": ["[SWAP]"] } ] },
                    { "name": "nvme0n1p3", "type": "part", "size": 1073741824, "mountpoints": [],
                      "children": [ { "name": "md1", "type": "raid1", "size": 1071644672, "mountpoints": ["/boot"] } ] },
                    { "name": "nvme0n1p4", "type": "part", "size": 477479902720, "mountpoints": [],
                      "children": [ { "name": "md2", "type": "raid1", "size": 477344628736, "mountpoints": ["/"] } ] }
                 ]
              }
           ]
        }"#;
        let parsed: LsblkOut = serde_json::from_str(raw).expect("real lsblk schema must parse");
        let inv = StorageInventory::from_devices(parsed.blockdevices.unwrap());

        // Unique root: md2 once.
        let roots = inv.root_devices();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].name, "md2");
        assert_eq!(roots[0].kind, "raid1");
        assert_eq!(roots[0].size_bytes, Some(477_344_628_736));

        // No free disks on this host.
        assert!(inv.free_disks().is_empty());

        // RAID sets: md0/md1/md2 with two members each.
        let sets = inv.raid_sets();
        let names: Vec<_> = sets.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"md2"));
        let md2 = sets.iter().find(|s| s.name == "md2").unwrap();
        assert_eq!(md2.level, "raid1");
        assert_eq!(md2.members.len(), 2);
        assert!(md2.mountpoints.iter().any(|m| m == "/"));

        // Swap not treated as root.
        let swap = inv.walk().into_iter().find(|d| d.name == "md0").unwrap();
        assert!(swap.is_swap());
        assert!(!swap.is_mounted_at_root());
    }

    /// Legacy singular `mountpoint` + string size still supported.
    #[test]
    fn parses_legacy_mountpoint_string_size() {
        let raw = r#"{"blockdevices":[
            {"name":"sda","type":"disk","size":"476.9G","mountpoint":"/","fstype":"ext4"}
        ]}"#;
        let parsed: LsblkOut = serde_json::from_str(raw).unwrap();
        let inv = StorageInventory::from_devices(parsed.blockdevices.unwrap());
        let root = inv.root_devices();
        assert_eq!(root[0].name, "sda");
        assert_eq!(root[0].size_bytes, Some(parse_size_str("476.9G").unwrap()));
        assert!(root[0].is_mounted_at_root());
    }
}
