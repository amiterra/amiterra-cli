//! Drift detection: `decompile(compiled tree)` vs `topology.yaml`
//! (Design Doc 0026 §1.3 — provenance labels make the repository reversible).
//!
//! Manual edits to the compiled tree are outside the model (I1): the next
//! apply overwrites them, but drift must be **visible** before that. The
//! comparison decompiles what Git actually holds and checks it against the
//! declared `topology.yaml` — the same source of truth the reviewer saw.

use amispec_compile::decompile;
use anyhow::{Context, Result};
use serde::Deserialize;

use super::agent::RepoWriter;

/// Outcome of a drift check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftReport {
    /// True when the decompiled tree and `topology.yaml` disagree.
    pub drifted: bool,
    /// Human-readable difference summary (empty when clean).
    pub details: Vec<String>,
}

impl DriftReport {
    pub fn summary(&self) -> String {
        if self.drifted {
            format!(
                "DRIFT ({} difference(s)): {}",
                self.details.len(),
                self.details.join("; ")
            )
        } else {
            "clean — decompiled tree matches topology.yaml".to_string()
        }
    }
}

/// Compare the compiled tree at repo HEAD with the declared topology.
pub fn detect(writer: &RepoWriter, topology_yaml: &str) -> Result<DriftReport> {
    let declared: amispec_schema::TopologyBlueprint =
        amispec_schema::parse_topology(topology_yaml).context("parse declared topology")?;
    let cluster_id = declared
        .clusters
        .first()
        .map(|c| c.id.clone())
        .unwrap_or_default();
    let prefix = format!("clusters/{cluster_id}/");

    // Collect the compiled YAML documents of the cluster directory.
    let mut docs: Vec<serde_yaml::Value> = Vec::new();
    for rel in writer.list_files(&prefix)? {
        if !rel.ends_with(".yaml") && !rel.ends_with(".yml") {
            continue;
        }
        // Sources are not compiled artifacts (Design 0026 §2.3) — the
        // decompile pass only reads the stage tree with provenance.
        if rel.ends_with("topology.yaml") || rel.contains("/flux-system/") {
            continue;
        }
        if let Some(content) = writer.read_file(&rel)? {
            for doc in serde_yaml::Deserializer::from_str(&content) {
                let value =
                    serde_yaml::Value::deserialize(doc).with_context(|| format!("parse {rel}"))?;
                docs.push(value);
            }
        }
    }

    let report = decompile(&docs);
    let Some(rebuilt) = report.topology else {
        return Ok(DriftReport {
            drifted: true,
            details: vec![
                "no AmiSpec provenance in the compiled tree (tree empty or hand-written)".into(),
            ],
        });
    };

    let mut details = Vec::new();
    compare(&declared, &rebuilt, &mut details);
    Ok(DriftReport {
        drifted: !details.is_empty(),
        details,
    })
}

fn compare(
    declared: &amispec_schema::TopologyBlueprint,
    rebuilt: &amispec_schema::TopologyBlueprint,
    out: &mut Vec<String>,
) {
    let d_ids: Vec<&str> = declared.clusters.iter().map(|c| c.id.as_str()).collect();
    let r_ids: Vec<&str> = rebuilt.clusters.iter().map(|c| c.id.as_str()).collect();
    if d_ids != r_ids {
        out.push(format!("clusters: declared {d_ids:?}, tree {r_ids:?}"));
    }
    for (d, r) in declared.clusters.iter().zip(rebuilt.clusters.iter()) {
        let mut d_comps: Vec<&str> = d.components.iter().map(|c| c.id.as_str()).collect();
        let mut r_comps: Vec<&str> = r.components.iter().map(|c| c.id.as_str()).collect();
        d_comps.sort();
        r_comps.sort();
        if d_comps != r_comps {
            out.push(format!(
                "cluster {}: components declared {d_comps:?}, tree {r_comps:?}",
                d.id
            ));
        }
        for comp in &d.components {
            let Some(rc) = r.components.iter().find(|c| c.id == comp.id) else {
                continue;
            };
            if comp.expose.len() != rc.expose.len() {
                out.push(format!(
                    "{}/expose: declared {}, tree {}",
                    comp.id,
                    comp.expose.len(),
                    rc.expose.len()
                ));
            }
            if comp.zone != rc.zone {
                out.push(format!(
                    "{}/zone: declared {:?}, tree {:?}",
                    comp.id, comp.zone, rc.zone
                ));
            }
            // `replicas: unset` compiles to `replicas: 1` — the tree can only
            // express concrete values, so normalize before comparing.
            if comp.topology.replicas.unwrap_or(1) != rc.topology.replicas.unwrap_or(1) {
                out.push(format!(
                    "{}/replicas: declared {:?}, tree {:?}",
                    comp.id, comp.topology.replicas, rc.topology.replicas
                ));
            }
            if comp.passport != rc.passport || comp.passport_rev != rc.passport_rev {
                out.push(format!(
                    "{}/passport: declared {}@rev{}, tree {}@rev{}",
                    comp.id, comp.passport, comp.passport_rev, rc.passport, rc.passport_rev
                ));
            }
        }
        let d_lbs: Vec<&str> = d.load_balancers.iter().map(|l| l.id.as_str()).collect();
        let r_lbs: Vec<&str> = r.load_balancers.iter().map(|l| l.id.as_str()).collect();
        if d_lbs != r_lbs {
            out.push(format!(
                "cluster {}: loadBalancers declared {d_lbs:?}, tree {r_lbs:?}",
                d.id
            ));
        }
    }
}

/// Serialize a topology canonically (drift comparison basis).
pub fn canonical(topology_yaml: &str) -> Result<String> {
    let topo = amispec_schema::parse_topology(topology_yaml)?;
    Ok(serde_yaml::to_string(&topo)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::agent::tests_support::{test_world, topology_yaml};

    fn commit_topo(writer: &RepoWriter, files: std::collections::BTreeMap<String, String>) {
        writer.commit(&files, "clusters/c0", &[], "test").unwrap();
    }

    #[test]
    fn clean_tree_has_no_drift() {
        let w = test_world();
        let cat = {
            let mut idx = amispec_compile::PassportIndex::new();
            idx.insert_document(crate::delivery::agent::tests_support::WEB_PASSPORT)
                .unwrap();
            idx
        };
        let yaml = topology_yaml("app.example.io");
        let topo = amispec_schema::parse_topology(&yaml).unwrap();
        let bundle = amispec_compile::build_bundle(&topo, "c0", &cat, true).unwrap();
        let writer = w.writer();
        commit_topo(&writer, bundle.repo_tree());

        let report = detect(&writer, &yaml).unwrap();
        assert!(!report.drifted, "{}", report.summary());
    }

    #[test]
    fn manual_tree_edit_is_visible_drift() {
        let w = test_world();
        let cat = {
            let mut idx = amispec_compile::PassportIndex::new();
            idx.insert_document(crate::delivery::agent::tests_support::WEB_PASSPORT)
                .unwrap();
            idx
        };
        let yaml = topology_yaml("app.example.io");
        let topo = amispec_schema::parse_topology(&yaml).unwrap();
        let bundle = amispec_compile::build_bundle(&topo, "c0", &cat, true).unwrap();
        let mut files = bundle.repo_tree();
        // V6: hand-edit the compiled tree (e.g. scale a deployment by hand)
        let wl = files
            .iter()
            .find(|(p, _)| p.contains("workloads.yaml"))
            .map(|(p, _)| p.clone())
            .unwrap();
        let edited = files[&wl].replace("replicas: 1", "replicas: 7");
        files.insert(wl, edited);
        let writer = w.writer();
        commit_topo(&writer, files);

        let report = detect(&writer, &yaml).unwrap();
        assert!(report.drifted, "hand edit must show as drift");
        assert!(!report.details.is_empty());
    }
}
