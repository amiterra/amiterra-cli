//! Signed `TopologyChange` intent (Design Doc 0026 §2.1, Design 0020 §4.2).
//!
//! An intent is the **only** way to change the fleet repository: a
//! schema-constrained payload (AmiSpec topology + catalog pins + the reviewed
//! `tree_hash`), signed with SSHSIG (Ed25519, namespace-bound) by a key the
//! agent allowlists. Idempotent by `change_id`; anti-replay by `nonce` + TTL.

use amispec_compile::CatalogPin;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

/// apiVersion of the intent payloads.
pub const INTENT_API_VERSION: &str = "intent.amiterra.io/v1";
/// SSHSIG namespace binding signatures to this protocol (anti cross-protocol).
pub const SIG_NAMESPACE: &str = "amiterra-intent";
/// Default intent TTL (seconds) — Design 0026 §2.1 example.
pub const DEFAULT_TTL_SECONDS: u32 = 900;
/// Maximum accepted TTL — a long-lived intent is a standing replay ticket.
pub const MAX_TTL_SECONDS: u32 = 86_400;
/// Clock-skew tolerance (seconds) between the door and the agent — a couple
/// of seconds of NTP drift must not reject a freshly signed intent.
pub const CLOCK_SKEW_TOLERANCE: i64 = 5;

/// Who initiated the change (Design Doc 0026 §2.1: console | local).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// console.amiterra.io (SaaS API signs with the platform key).
    Console,
    /// Local door (`ami apply`) — signed with the operator key.
    Local,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Origin::Console => "console",
            Origin::Local => "local",
        })
    }
}

/// `metadata` of a [`TopologyChange`] (snake_case per Design 0026 §2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentMeta {
    /// Idempotency key: `chg-<16 hex>`; the journal file is named after it.
    pub change_id: String,
    /// Random anti-replay value (32 hex chars).
    pub nonce: String,
    /// Lifetime in seconds from [`Self::created_at`].
    #[serde(rename = "ttl_seconds")]
    pub ttl_seconds: u32,
    /// RFC3339 UTC creation time.
    #[serde(rename = "created_at")]
    pub created_at: String,
}

/// `spec` of a [`TopologyChange`] (camelCase per Design 0026 §2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSpec {
    #[serde(rename = "clusterId")]
    pub cluster_id: String,
    pub origin: Origin,
    /// Human/machine actor id for the audit trail.
    pub actor: String,
    /// Compiler/standard version of the preview phase (skew detection).
    #[serde(rename = "amispecVersion")]
    pub amispec_version: String,
    /// `tree_hash` the reviewer saw — the review↔result binding.
    #[serde(rename = "expectedTreeHash")]
    pub expected_tree_hash: String,
    /// Schema hash of the preview (topology + resolved pins).
    #[serde(rename = "schemaHash")]
    pub schema_hash: String,
    /// Catalog pins with content (id@rev + content + sha256) — the agent
    /// compiles from these, never from the SaaS catalog directly.
    #[serde(rename = "catalogPins")]
    pub catalog_pins: Vec<CatalogPin>,
    /// Desired `TopologyBlueprint` YAML for `clusters/<id>/topology.yaml`
    /// (replace semantics — v1 of the "semantic patch" of Design 0026 §2.1).
    #[serde(rename = "topologyDelta")]
    pub topology_delta: String,
}

/// The signed change request (`kind: TopologyChange`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyChange {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: IntentMeta,
    pub spec: IntentSpec,
}

/// Meta of the audit journal record (`_intent/<change-id>.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMeta {
    pub change_id: String,
    #[serde(rename = "appliedAt")]
    pub applied_at: String,
}

/// Spec of the audit journal record (Design Doc 0026 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSpec {
    pub origin: Origin,
    pub actor: String,
    #[serde(rename = "clusterId")]
    pub cluster_id: String,
    #[serde(rename = "amispecVersion")]
    pub amispec_version: String,
    /// Tree hash the agent computed (== expected, or the apply was refused).
    #[serde(rename = "treeHash")]
    pub tree_hash: String,
    #[serde(rename = "schemaHash")]
    pub schema_hash: String,
    /// Hash of the `topology.yaml` content that landed in Git.
    #[serde(rename = "topologySha256")]
    pub topology_sha256: String,
    /// SSHSIG fingerprint of the signing key (`SHA256:…`), never key material.
    #[serde(rename = "signatureFingerprint")]
    pub signature_fingerprint: String,
    /// Commit the change built on — rollback base (V5).
    #[serde(rename = "prevHead")]
    pub prev_head: String,
    /// `applied` (committed) | `noop` (change_id already journaled).
    pub status: String,
    /// Pin identities (content lives in `catalog/`, not repeated here).
    #[serde(rename = "catalogPins")]
    pub catalog_pins: Vec<amispec_compile::PinMeta>,
}

/// Audit journal entry written by the agent as `_intent/<change-id>.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyChangeRecord {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: RecordMeta,
    pub spec: RecordSpec,
}

impl TopologyChange {
    /// Canonical serialization — the exact bytes signed and verified.
    ///
    /// Struct field order is fixed by the type, so the same intent always
    /// yields the same bytes across doors, versions and platforms.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let yaml = serde_yaml::to_string(self).context("serialize TopologyChange")?;
        Ok(yaml.into_bytes())
    }

    /// Validate structural invariants of a received intent.
    pub fn validate_shape(&self) -> Result<()> {
        if self.api_version != INTENT_API_VERSION {
            bail!(
                "unsupported intent apiVersion `{}` (expected {INTENT_API_VERSION})",
                self.api_version
            );
        }
        if self.kind != "TopologyChange" {
            bail!(
                "unsupported intent kind `{}` (expected TopologyChange)",
                self.kind
            );
        }
        validate_change_id(&self.metadata.change_id)?;
        validate_nonce(&self.metadata.nonce)?;
        if self.metadata.ttl_seconds == 0 || self.metadata.ttl_seconds > MAX_TTL_SECONDS {
            bail!(
                "ttl_seconds {} outside 1..={MAX_TTL_SECONDS}",
                self.metadata.ttl_seconds
            );
        }
        validate_token(&self.spec.cluster_id, "clusterId")?;
        if self.spec.catalog_pins.is_empty() {
            bail!("catalogPins MUST NOT be empty");
        }
        for pin in &self.spec.catalog_pins {
            if !pin.verify_content() {
                bail!(
                    "catalog pin {}/rev{}: sha256 does not match content",
                    pin.id,
                    pin.rev
                );
            }
            validate_token(&pin.id, "catalog pin id")?;
        }
        if self.spec.topology_delta.trim().is_empty() {
            bail!("topologyDelta MUST NOT be empty");
        }
        if !self.spec.expected_tree_hash.starts_with("sha256:") {
            bail!("expectedTreeHash MUST be a sha256:<hex> value");
        }
        Ok(())
    }

    /// Journal filename derived from the change id (already validated shape).
    pub fn journal_path(&self) -> String {
        format!("_intent/{}.yaml", self.metadata.change_id)
    }
}

impl TopologyChangeRecord {
    pub fn new(
        change: &TopologyChange,
        applied_at: String,
        tree_hash: &str,
        signature_fingerprint: &str,
        prev_head: &str,
        status: &str,
    ) -> Self {
        Self {
            api_version: INTENT_API_VERSION.to_string(),
            kind: "TopologyChangeRecord".to_string(),
            metadata: RecordMeta {
                change_id: change.metadata.change_id.clone(),
                applied_at,
            },
            spec: RecordSpec {
                origin: change.spec.origin,
                actor: change.spec.actor.clone(),
                cluster_id: change.spec.cluster_id.clone(),
                amispec_version: change.spec.amispec_version.clone(),
                tree_hash: tree_hash.to_string(),
                schema_hash: change.spec.schema_hash.clone(),
                topology_sha256: hash_text(&change.spec.topology_delta),
                signature_fingerprint: signature_fingerprint.to_string(),
                prev_head: prev_head.to_string(),
                status: status.to_string(),
                catalog_pins: change.spec.catalog_pins.iter().map(Into::into).collect(),
            },
        }
    }

    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).context("serialize TopologyChangeRecord")
    }
}

/// Read the `_intent/` journal from a repository (audit + rollback base,
/// Design Doc 0026 §2.2). Entries are returned sorted by `change_id`
/// (journal order is commit order — apply appends one file per delivery).
pub fn journal_entries(
    writer: &crate::delivery::agent::RepoWriter,
) -> Result<Vec<TopologyChangeRecord>> {
    let mut out = Vec::new();
    for rel in writer.list_files("_intent/")? {
        if !rel.ends_with(".yaml") {
            continue;
        }
        let Some(content) = writer.read_file(&rel)? else {
            continue;
        };
        let record: TopologyChangeRecord =
            serde_yaml::from_str(&content).with_context(|| format!("parse journal entry {rel}"))?;
        out.push(record);
    }
    out.sort_by(|a, b| a.metadata.change_id.cmp(&b.metadata.change_id));
    Ok(out)
}

/// `sha256:<hex>` of arbitrary text (journal content hashes).
pub fn hash_text(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    format!("sha256:{}", to_hex(&h.finalize()))
}

/// Hex-encode digest output (sha2 0.11 `Array` has no `LowerHex`).
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Random anti-replay nonce (16 bytes → 32 hex chars) from the OS CSPRNG.
pub fn generate_nonce() -> Result<String> {
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
        .context("read /dev/urandom")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Deterministic change id: `chg-<16 hex>` over the replay-relevant fields.
pub fn derive_change_id(
    nonce: &str,
    created_at: &str,
    cluster_id: &str,
    tree_hash: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(nonce.as_bytes());
    h.update(b"\0");
    h.update(created_at.as_bytes());
    h.update(b"\0");
    h.update(cluster_id.as_bytes());
    h.update(b"\0");
    h.update(tree_hash.as_bytes());
    let hex = to_hex(&h.finalize());
    format!("chg-{}", &hex[..16])
}

/// Build a fully-formed intent (metadata derived from the spec inputs).
pub fn build_intent(
    spec: IntentSpec,
    nonce: String,
    created_at: String,
    ttl_seconds: u32,
) -> Result<TopologyChange> {
    let change_id = derive_change_id(
        &nonce,
        &created_at,
        &spec.cluster_id,
        &spec.expected_tree_hash,
    );
    let intent = TopologyChange {
        api_version: INTENT_API_VERSION.to_string(),
        kind: "TopologyChange".to_string(),
        metadata: IntentMeta {
            change_id,
            nonce,
            ttl_seconds,
            created_at,
        },
        spec,
    };
    intent.validate_shape()?;
    Ok(intent)
}

/// Sign the canonical intent bytes with SSHSIG (Ed25519, namespace-bound).
/// Returns the signature in PEM form for transport and journaling.
pub fn sign_intent(intent: &TopologyChange, key: &PrivateKey) -> Result<String> {
    let bytes = intent.canonical_bytes()?;
    let sig = key
        .sign(SIG_NAMESPACE, HashAlg::Sha256, &bytes)
        .map_err(|e| anyhow!("intent signing failed: {e}"))?;
    sig.to_pem(LineEnding::LF).context("encode signature")
}

/// Result of a successful signature check.
#[derive(Debug, Clone)]
pub struct VerifiedSigner {
    /// SSHSIG fingerprint (`SHA256:…`) of the allowlisted key.
    pub fingerprint: String,
}

/// Verify an intent signature against an allowlist of public keys
/// (Design 0020 §4.3: signature + allowlist before anything else).
pub fn verify_intent(
    intent: &TopologyChange,
    signature_pem: &str,
    allowlist: &[PublicKey],
) -> Result<VerifiedSigner> {
    if allowlist.is_empty() {
        bail!("intent allowlist is empty — refusing every intent");
    }
    let sig = SshSig::from_pem(signature_pem).context("parse intent signature")?;
    if sig.namespace() != SIG_NAMESPACE {
        bail!(
            "signature namespace `{}` != `{SIG_NAMESPACE}` (cross-protocol replay)",
            sig.namespace()
        );
    }
    let bytes = intent.canonical_bytes()?;
    // SshSig embeds the signer's public key (PROTOCOL.sshsig).
    let signer = PublicKey::from(sig.public_key().clone());
    let fp = signer.fingerprint(HashAlg::Sha256).to_string();
    let allowed = allowlist
        .iter()
        .any(|k| k.fingerprint(HashAlg::Sha256).to_string() == fp);
    if !allowed {
        bail!("signer key {fp} is not in the intent allowlist");
    }
    signer
        .verify(SIG_NAMESPACE, &bytes, &sig)
        .map_err(|_| anyhow!("intent signature verification failed (payload tampered?)"))?;
    Ok(VerifiedSigner { fingerprint: fp })
}

/// TTL freshness check (anti-replay, Design 0020 §4.3).
pub fn is_fresh(created_at: &str, ttl_seconds: u32, now_epoch: i64) -> Result<()> {
    let created = parse_rfc3339_utc(created_at)
        .ok_or_else(|| anyhow!("created_at `{created_at}` is not RFC3339 UTC (…Z)"))?;
    if now_epoch + CLOCK_SKEW_TOLERANCE < created {
        bail!("intent created_at {created_at} is more than {CLOCK_SKEW_TOLERANCE}s in the future");
    }
    if now_epoch > created + i64::from(ttl_seconds) {
        bail!("intent expired: created_at {created_at} + {ttl_seconds}s < now ({now_epoch})");
    }
    Ok(())
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (the shape `now_rfc3339` emits) to epoch secs.
pub fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let (time, tail) = rest.split_once('Z')?;
    if !tail.is_empty() {
        return None;
    }
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let mo: i64 = d.next()?.parse().ok()?;
    let da: i64 = d.next()?.parse().ok()?;
    if d.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return None;
    }
    let mut t = time.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next()?.parse().ok()?;
    let ss: i64 = t.next()?.parse().ok()?;
    if t.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // days-from-civil (Howard Hinnant) + time of day
    let m = mo;
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// `change_id` grammar: `chg-` + exactly 16 lowercase hex chars.
/// This value becomes a **filename** — the grammar is a security boundary
/// (no path separators, no traversal).
pub fn validate_change_id(id: &str) -> Result<()> {
    let ok = id.len() == 20
        && id.starts_with("chg-")
        && id[4..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !ok {
        bail!("invalid change_id `{id}`: expected chg-<16 lowercase hex>");
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<()> {
    let ok = nonce.len() == 32 && nonce.chars().all(|c| c.is_ascii_hexdigit());
    if !ok {
        bail!("invalid nonce `{nonce}`: expected 32 hex chars");
    }
    Ok(())
}

/// Load the agent's intent allowlist: one OpenSSH public key per `*.pub`
/// file in `dir` (the file may carry a comment after the key type).
///
/// Only keys listed here can move the fleet repository; the directory is the
/// operator-managed trust root (platform key + operator keys, Design 0020 §5).
pub fn load_allowlist(dir: &std::path::Path) -> Result<Vec<PublicKey>> {
    let mut keys = Vec::new();
    if !dir.is_dir() {
        return Ok(keys);
    }
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read allowlist {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .collect();
    entries.sort();
    for path in entries {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read allowlist entry {}", path.display()))?;
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("ssh-") && !l.is_empty())
            .ok_or_else(|| anyhow!("no OpenSSH public key in {}", path.display()))?;
        let key = PublicKey::from_openssh(line)
            .with_context(|| format!("parse allowlist entry {}", path.display()))?;
        keys.push(key);
    }
    Ok(keys)
}

/// Operator intent key paths under a base dir (`gitops` state dir).
pub fn operator_key_paths(base: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        base.join("operator-intent-key"),
        base.join("operator-intent-key.pub"),
    )
}

/// Ensure the operator intent key pair exists (created locally, never
/// uploaded — Design 0026 §1.7: the key only signs intents, its public part
/// is added to the agent allowlist).
pub fn ensure_operator_key(base: &std::path::Path) -> Result<crate::gitops::keys::DeployKey> {
    let (private, _) = operator_key_paths(base);
    std::fs::create_dir_all(base).with_context(|| format!("create {}", base.display()))?;
    crate::gitops::keys::ensure(&private).context("ensure operator intent key")
}

/// Conservative token grammar for values used in repo paths (mirrors
/// `gitops::validate_token`: no whitespace/quotes/traversal).
pub fn validate_token(value: &str, what: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !value.starts_with('-')
        && !value.contains("..");
    if !ok {
        bail!(
            "invalid {what} `{value}`: ASCII letters, digits, '.', '_', '-' only \
             (max 63 chars, no leading '-', no '..')"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (PrivateKey, PublicKey) {
        let priv_path = std::env::temp_dir().join(format!(
            "amiterra-intent-test-{}-{}",
            std::process::id(),
            generate_nonce().unwrap()
        ));
        let key = crate::gitops::keys::generate(&priv_path).unwrap();
        let private = PrivateKey::read_openssh_file(&priv_path).unwrap();
        let public = PublicKey::from_openssh(&key.public_line).unwrap();
        let _ = std::fs::remove_file(&priv_path);
        let _ = std::fs::remove_file(priv_path.with_extension("pub"));
        (private, public)
    }

    fn sample_pin() -> CatalogPin {
        let content = "apiVersion: catalog.amispec.io/v1\nkind: ComponentPassport\n";
        CatalogPin {
            id: "stateless-app".into(),
            version: "1.0.0".into(),
            rev: 1,
            sha256: amispec_compile::bundle::hash_content(content),
            path: "catalog/stateless-app/rev1.yaml".into(),
            content: content.into(),
        }
    }

    fn sample_spec() -> IntentSpec {
        IntentSpec {
            cluster_id: "c0".into(),
            origin: Origin::Local,
            actor: "operator@node1".into(),
            amispec_version: "amispec-compile/0.2.0+1.0.0".into(),
            expected_tree_hash: "sha256:abc".into(),
            schema_hash: "sha256:def".into(),
            catalog_pins: vec![sample_pin()],
            topology_delta: "apiVersion: topology.amispec.io/v1\nkind: TopologyBlueprint\n".into(),
        }
    }

    fn sample_intent() -> TopologyChange {
        build_intent(
            sample_spec(),
            "00112233445566778899aabbccddeeff".into(),
            "2026-11-01T12:00:00Z".into(),
            900,
        )
        .unwrap()
    }

    #[test]
    fn change_id_is_deterministic_and_well_formed() {
        let a = derive_change_id("n", "2026-11-01T12:00:00Z", "c0", "sha256:abc");
        let b = derive_change_id("n", "2026-11-01T12:00:00Z", "c0", "sha256:abc");
        let c = derive_change_id("n", "2026-11-01T12:00:01Z", "c0", "sha256:abc");
        assert_eq!(a, b);
        assert_ne!(a, c);
        validate_change_id(&a).unwrap();
        assert!(validate_change_id("chg-../etc/passwd").is_err());
        assert!(validate_change_id("chg-XYZ").is_err());
        assert!(validate_change_id("chg-0123456789abcdef0").is_err());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, pk) = keypair();
        let intent = sample_intent();
        let pem = sign_intent(&intent, &sk).unwrap();
        let v = verify_intent(&intent, &pem, std::slice::from_ref(&pk)).unwrap();
        assert!(v.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, pk) = keypair();
        let intent = sample_intent();
        let pem = sign_intent(&intent, &sk).unwrap();
        let mut tampered = intent.clone();
        tampered.spec.expected_tree_hash = "sha256:evil".into();
        assert!(verify_intent(&tampered, &pem, &[pk]).is_err());
    }

    #[test]
    fn verify_rejects_non_allowlisted_signer() {
        let (sk, _pk) = keypair();
        let (_sk2, pk2) = keypair();
        let intent = sample_intent();
        let pem = sign_intent(&intent, &sk).unwrap();
        assert!(verify_intent(&intent, &pem, &[pk2]).is_err());
    }

    #[test]
    fn verify_rejects_empty_allowlist() {
        let (sk, _pk) = keypair();
        let intent = sample_intent();
        let pem = sign_intent(&intent, &sk).unwrap();
        assert!(verify_intent(&intent, &pem, &[]).is_err());
    }

    #[test]
    fn freshness_window_is_enforced() {
        let now = parse_rfc3339_utc("2026-11-01T12:10:00Z").unwrap();
        assert!(is_fresh("2026-11-01T12:00:00Z", 900, now).is_ok());
        assert!(
            is_fresh("2026-11-01T12:00:00Z", 300, now).is_err(),
            "expired"
        );
        assert!(
            is_fresh("2026-11-01T12:30:00Z", 900, now).is_err(),
            "future"
        );
        assert!(is_fresh("not-a-date", 900, now).is_err());
    }

    #[test]
    fn rfc3339_roundtrip_matches_now_formatter() {
        let t = crate::gitops::state::now_rfc3339();
        let epoch = parse_rfc3339_utc(&t).unwrap();
        // second-precision round trip: parse(format(t)) == t
        assert_eq!(epoch, parse_rfc3339_utc(&t).unwrap());
    }

    #[test]
    fn pin_hash_mismatch_fails_shape_validation() {
        let mut intent = sample_intent();
        intent.spec.catalog_pins[0].sha256 = "sha256:dead".into();
        assert!(intent.validate_shape().is_err());
    }

    #[test]
    fn journal_record_yaml_roundtrip() {
        let intent = sample_intent();
        let rec = TopologyChangeRecord::new(
            &intent,
            "2026-11-01T12:01:00Z".into(),
            "sha256:abc",
            "SHA256:fp",
            "prevsha",
            "applied",
        );
        let yaml = rec.to_yaml().unwrap();
        assert!(yaml.contains("TopologyChangeRecord"));
        assert!(yaml.contains("prevHead"));
        assert!(!yaml.contains("content"), "journal holds pin meta only");
        let back: TopologyChangeRecord = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn intent_yaml_roundtrip_is_canonical() {
        let intent = sample_intent();
        let bytes = intent.canonical_bytes().unwrap();
        let back: TopologyChange = serde_yaml::from_slice(&bytes).unwrap();
        assert_eq!(back, intent);
        assert_eq!(
            back.canonical_bytes().unwrap(),
            bytes,
            "canonical form is stable"
        );
    }

    #[test]
    fn allowlist_loads_pub_files_and_skips_noise() {
        let dir = tempfile::tempdir().unwrap();
        let (_sk, pk) = keypair();
        let line = pk.to_openssh().unwrap();
        std::fs::write(
            dir.path().join("operator.pub"),
            format!("{line} operator@node1\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "ignore me").unwrap();
        std::fs::write(dir.path().join("broken.pub"), "not a key").unwrap();
        // broken.pub must fail loudly — a silently-skipped allowlist entry
        // would silently widen or narrow the trust root
        assert!(load_allowlist(dir.path()).is_err());

        std::fs::remove_file(dir.path().join("broken.pub")).unwrap();
        let keys = load_allowlist(dir.path()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].fingerprint(HashAlg::Sha256).to_string(),
            pk.fingerprint(HashAlg::Sha256).to_string()
        );
    }

    #[test]
    fn missing_allowlist_dir_is_empty_not_error() {
        let dir = std::path::Path::new("/nonexistent-amiterra-allowlist");
        assert!(load_allowlist(dir).unwrap().is_empty());
    }

    #[test]
    fn operator_key_is_created_locally_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let key = ensure_operator_key(dir.path()).unwrap();
        assert!(key.public_line.starts_with("ssh-ed25519 "));
        let again = ensure_operator_key(dir.path()).unwrap();
        assert_eq!(key.public_line, again.public_line, "idempotent");
        let (priv_path, _) = operator_key_paths(dir.path());
        assert!(
            priv_path.exists(),
            "private key stays on disk (never uploaded)"
        );
    }

    #[test]
    fn rfc3339_parser_accepts_only_z_shape() {
        assert!(parse_rfc3339_utc("2026-11-01T12:00:00Z").is_some());
        assert!(parse_rfc3339_utc("2026-11-01T12:00:00+02:00").is_none());
        assert!(parse_rfc3339_utc("2026-13-01T12:00:00Z").is_none());
    }
}
