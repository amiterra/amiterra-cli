//! Optional feature governance for `ami init` / `ami join`.
//!
//! One resolution pipeline for every optional layer (storage, tuning, GitOps):
//!
//! 1. `--all-features` — every applicable feature ON, no prompts;
//! 2. per-feature flags (`--storage-disk`, `--tune-apply`, `--gitops-bootstrap`);
//! 3. interactive prompts (safe default is always Skip);
//! 4. `--yes` — everything stays OFF (base install only).
//!
//! `--yes` never means "all features": full installs require the explicit
//! `--all-features` key. Feature applicability is contextual — e.g. GitOps
//! bootstrap is cluster-scoped and only applies to the control-plane-init node.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Decision for one optional feature layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureDecision {
    /// Apply the feature.
    pub enabled: bool,
    /// Feature applies to this command context at all (role, host, target).
    pub applicable: bool,
}

impl FeatureDecision {
    pub const OFF: Self = Self {
        enabled: false,
        applicable: true,
    };

    pub fn on() -> Self {
        Self {
            enabled: true,
            applicable: true,
        }
    }

    pub fn not_applicable() -> Self {
        Self {
            enabled: false,
            applicable: false,
        }
    }
}

/// Outcome of the storage feature for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StoragePlan {
    /// Leave the node on shared root (tier s0).
    #[default]
    Skip,
    /// Dedicated VG already exists — converge activation (LV + mount) only.
    Activate,
    /// Prepare this unallocated disk (LVM) and activate it.
    Prepare(String),
}

/// Final per-feature plan for one init/join run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeaturePlan {
    /// Dedicated data disk handling (None-safe enum, see [`StoragePlan`]).
    pub storage: StoragePlan,
    /// Apply the performance profile.
    pub tune: FeatureDecision,
    /// Bootstrap GitOps (cluster-scoped: control-plane-init only).
    pub gitops: FeatureDecision,
}

impl FeaturePlan {
    /// Base-only plan (`--yes` semantics).
    pub fn base_only() -> Self {
        Self {
            storage: StoragePlan::Skip,
            tune: FeatureDecision::OFF,
            gitops: FeatureDecision::OFF,
        }
    }

    pub fn any_enabled(&self) -> bool {
        self.storage != StoragePlan::Skip || self.tune.enabled || self.gitops.enabled
    }
}

/// CLI inputs that drive feature resolution.
#[derive(Debug, Clone, Default)]
pub struct FeatureRequest {
    pub all_features: bool,
    pub storage_disk: Option<String>,
    pub tune_apply: bool,
    pub gitops_bootstrap: bool,
}

/// Context facts that decide applicability and storage auto-selection.
#[derive(Debug, Clone, Default)]
pub struct FeatureContext {
    /// True for the cluster-init node (GitOps bootstrap is cluster-scoped).
    pub cluster_init: bool,
    /// True for the production server target (storage/LVM is a server feature).
    pub server: bool,
    /// Names of unallocated whole disks eligible for `storage prepare`.
    pub free_disks: Vec<String>,
    /// True when the dedicated VG already exists (re-run: converge activation).
    pub vg_present: bool,
    /// Whether the user interactively answers prompts (TTY without `--yes`).
    pub interactive: bool,
}

/// UI port for undecided features. Implemented by the wizard; mocked in tests.
pub trait FeaturePrompts {
    /// Full storage step (Skip / Prepare / Preview).
    fn storage(&mut self, ctx: &FeatureContext) -> Result<StoragePlan>;
    /// Disk picker only — the feature is already ON and several disks qualify.
    fn disk(&mut self, candidates: &[String]) -> Result<String>;
    fn tune(&mut self) -> Result<bool>;
    fn gitops(&mut self) -> Result<bool>;
}

/// Outcome of flag-level resolution: what is already decided, what may prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// Decided by flags (`--all-features` or per-feature flag).
    On,
    /// Explicitly off / not applicable — never prompt.
    Off,
    /// Undecided: interactive prompt may still enable it.
    Prompt,
}

/// Pure flag-level resolution for one feature (unit-tested).
pub fn resolve_flag(all_features: bool, feature_flag: bool, applicable: bool) -> Resolved {
    if !applicable {
        Resolved::Off
    } else if feature_flag || all_features {
        Resolved::On
    } else {
        Resolved::Prompt
    }
}

/// Storage disk auto-selection policy for `--all-features` (unit-tested).
///
/// * exactly one free disk → auto-select it;
/// * zero free disks → `Ok(None)` (feature is not applicable here);
/// * two or more → `Err`: choosing destructively must be explicit
///   (`--storage-disk`), never a silent guess.
pub fn select_storage_disk(
    free_disks: &[String],
    explicit: Option<&str>,
) -> Result<Option<String>> {
    if let Some(disk) = explicit {
        let disk = disk.trim().trim_start_matches("/dev/").to_string();
        if disk.is_empty() {
            bail!("--storage-disk must not be empty");
        }
        if !free_disks.iter().any(|d| d == &disk) {
            bail!(
                "disk '{disk}' is not an unallocated free disk (available: {}). \
                 Nothing is modified — see `ami storage plan`.",
                if free_disks.is_empty() {
                    "none".to_string()
                } else {
                    free_disks.join(", ")
                }
            );
        }
        return Ok(Some(disk));
    }
    match free_disks.len() {
        0 => Ok(None),
        1 => Ok(Some(free_disks[0].clone())),
        n => bail!(
            "{n} unallocated disks found ({}); refusing to pick one implicitly. \
             Re-run with --storage-disk <name> (see `ami storage plan`).",
            free_disks.join(", ")
        ),
    }
}

/// Build the final plan from flags, context and prompt answers.
///
/// Prompt methods run only for undecided features (`Resolved::Prompt`) in an
/// interactive session, and for the disk *parameter* when `--all-features`
/// (or `--storage-disk`) leaves the disk ambiguous — collecting a parameter is
/// not the same decision as enabling a feature.
pub fn plan_features(
    req: &FeatureRequest,
    ctx: &FeatureContext,
    prompts: &mut impl FeaturePrompts,
) -> Result<FeaturePlan> {
    let tune_flag = resolve_flag(req.all_features, req.tune_apply, true);
    let gitops_flag = resolve_flag(req.all_features, req.gitops_bootstrap, ctx.cluster_init);
    // Storage is server-scoped. Applicable when the dedicated VG already exists
    // (converge activation), an explicit disk is requested, or a free disk
    // offers the upgrade path.
    let storage_flag = resolve_flag(
        req.all_features,
        req.storage_disk.is_some(),
        ctx.server && (ctx.vg_present || req.storage_disk.is_some() || !ctx.free_disks.is_empty()),
    );

    // Prompt order matches execution order in init: storage → tune → gitops.
    // (Asking about storage last while it runs first would confuse operators.)
    let storage = match storage_flag {
        // Converge path: VG already prepared — never re-pick a disk.
        Resolved::On if ctx.vg_present && req.storage_disk.is_none() => StoragePlan::Activate,
        // Feature ON without an explicit disk and several candidates → the
        // picker collects the parameter (interactive) or the policy errors
        // (non-interactive: destructive choice must be explicit).
        Resolved::On
            if req.storage_disk.is_none() && ctx.free_disks.len() > 1 && ctx.interactive =>
        {
            StoragePlan::Prepare(prompts.disk(&ctx.free_disks)?)
        }
        Resolved::On => match select_storage_disk(&ctx.free_disks, req.storage_disk.as_deref())? {
            Some(disk) => StoragePlan::Prepare(disk),
            // zero free disks and no VG → not applicable, keep s0.
            None => StoragePlan::Skip,
        },
        Resolved::Prompt if ctx.interactive => prompts.storage(ctx)?,
        _ => StoragePlan::Skip,
    };

    let tune = match tune_flag {
        Resolved::On => FeatureDecision::on(),
        Resolved::Off => FeatureDecision::OFF,
        Resolved::Prompt if ctx.interactive => {
            if prompts.tune()? {
                FeatureDecision::on()
            } else {
                FeatureDecision::OFF
            }
        }
        Resolved::Prompt => FeatureDecision::OFF,
    };

    let gitops = match gitops_flag {
        Resolved::On if ctx.cluster_init => FeatureDecision::on(),
        // Cluster-scoped: silently inapplicable on join nodes even under
        // `--all-features` (the C1 gate forbids rebinding there).
        Resolved::On => FeatureDecision::not_applicable(),
        Resolved::Off => {
            if ctx.cluster_init {
                FeatureDecision::OFF
            } else {
                FeatureDecision::not_applicable()
            }
        }
        Resolved::Prompt if ctx.interactive => {
            if prompts.gitops()? {
                FeatureDecision::on()
            } else {
                FeatureDecision::OFF
            }
        }
        Resolved::Prompt => FeatureDecision::OFF,
    };

    Ok(FeaturePlan {
        storage,
        tune,
        gitops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test double: records which prompts ran and returns canned answers.
    #[derive(Default)]
    struct FakePrompts {
        storage_answer: StoragePlan,
        disk_answer: String,
        tune_answer: bool,
        gitops_answer: bool,
        calls: Vec<&'static str>,
    }

    impl FeaturePrompts for FakePrompts {
        fn storage(&mut self, _ctx: &FeatureContext) -> Result<StoragePlan> {
            self.calls.push("storage");
            Ok(self.storage_answer.clone())
        }
        fn disk(&mut self, candidates: &[String]) -> Result<String> {
            self.calls.push("disk");
            assert!(!candidates.is_empty());
            Ok(self.disk_answer.clone())
        }
        fn tune(&mut self) -> Result<bool> {
            self.calls.push("tune");
            Ok(self.tune_answer)
        }
        fn gitops(&mut self) -> Result<bool> {
            self.calls.push("gitops");
            Ok(self.gitops_answer)
        }
    }

    impl FakePrompts {
        fn with_answers(tune: bool, gitops: bool) -> Self {
            Self {
                tune_answer: tune,
                gitops_answer: gitops,
                ..Default::default()
            }
        }
    }

    #[test]
    fn flag_priority_all_features_beats_everything() {
        assert_eq!(resolve_flag(true, false, true), Resolved::On);
        assert_eq!(resolve_flag(true, true, true), Resolved::On);
    }

    #[test]
    fn per_feature_flag_enables_without_all() {
        assert_eq!(resolve_flag(false, true, true), Resolved::On);
    }

    #[test]
    fn undecided_prompts_only_when_applicable() {
        assert_eq!(resolve_flag(false, false, true), Resolved::Prompt);
        assert_eq!(resolve_flag(false, false, false), Resolved::Off);
        // Feature flag cannot resurrect a non-applicable feature.
        assert_eq!(resolve_flag(true, true, false), Resolved::Off);
    }

    #[test]
    fn select_disk_single_free_disk_auto_selects() {
        let d = select_storage_disk(&["nvme1n1".into()], None).unwrap();
        assert_eq!(d.as_deref(), Some("nvme1n1"));
    }

    #[test]
    fn select_disk_zero_free_disks_is_not_applicable() {
        assert_eq!(select_storage_disk(&[], None).unwrap(), None);
    }

    #[test]
    fn select_disk_multiple_requires_explicit_choice() {
        let err = select_storage_disk(&["nvme1n1".into(), "nvme2n1".into()], None).unwrap_err();
        assert!(err.to_string().contains("--storage-disk"));
    }

    #[test]
    fn select_disk_explicit_validates_membership() {
        let d =
            select_storage_disk(&["nvme1n1".into(), "nvme2n1".into()], Some("nvme2n1")).unwrap();
        assert_eq!(d.as_deref(), Some("nvme2n1"));
        // /dev/ prefix is normalized away.
        let d = select_storage_disk(&["nvme1n1".into()], Some("/dev/nvme1n1")).unwrap();
        assert_eq!(d.as_deref(), Some("nvme1n1"));
        // Unknown or occupied disk is a hard error — nothing is modified.
        assert!(select_storage_disk(&["nvme1n1".into()], Some("sda")).is_err());
    }

    fn server_ctx(free: &[&str]) -> FeatureContext {
        FeatureContext {
            cluster_init: true,
            server: true,
            free_disks: free.iter().map(|s| s.to_string()).collect(),
            vg_present: false,
            interactive: false,
        }
    }

    #[test]
    fn yes_semantics_keep_everything_off() {
        // --yes: no flags, no prompts run → base only.
        let req = FeatureRequest::default();
        let ctx = server_ctx(&["nvme1n1"]);
        let mut prompts = FakePrompts::default();
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert_eq!(plan, FeaturePlan::base_only());
        assert!(!plan.any_enabled());
        assert!(prompts.calls.is_empty(), "--yes must not prompt");
    }

    #[test]
    fn all_features_enables_tune_and_gitops_on_cluster_init() {
        let req = FeatureRequest {
            all_features: true,
            ..Default::default()
        };
        // Zero free disks, no VG: storage not applicable, the rest is ON.
        let ctx = server_ctx(&[]);
        let mut prompts = FakePrompts::default();
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert!(plan.tune.enabled);
        assert!(plan.gitops.enabled);
        assert_eq!(plan.storage, StoragePlan::Skip);
    }

    #[test]
    fn all_features_single_disk_prepares_without_picker() {
        let req = FeatureRequest {
            all_features: true,
            ..Default::default()
        };
        let mut ctx = server_ctx(&["nvme1n1"]);
        ctx.interactive = true;
        let mut prompts = FakePrompts::default();
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert_eq!(plan.storage, StoragePlan::Prepare("nvme1n1".into()));
        assert!(
            !prompts.calls.contains(&"disk"),
            "single disk must not open a picker"
        );
    }

    #[test]
    fn all_features_multiple_disks_interactive_uses_picker() {
        let req = FeatureRequest {
            all_features: true,
            ..Default::default()
        };
        let mut ctx = server_ctx(&["nvme1n1", "nvme2n1"]);
        ctx.interactive = true;
        let mut prompts = FakePrompts {
            disk_answer: "nvme2n1".into(),
            ..Default::default()
        };
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert_eq!(plan.storage, StoragePlan::Prepare("nvme2n1".into()));
        assert!(prompts.calls.contains(&"disk"));
    }

    #[test]
    fn all_features_multiple_disks_non_interactive_fails_closed() {
        let req = FeatureRequest {
            all_features: true,
            ..Default::default()
        };
        let ctx = server_ctx(&["nvme1n1", "nvme2n1"]);
        let mut prompts = FakePrompts::default();
        let err = plan_features(&req, &ctx, &mut prompts).unwrap_err();
        assert!(err.to_string().contains("--storage-disk"));
    }

    #[test]
    fn existing_vg_converges_to_activation_without_disk_picker() {
        // Re-run after `storage prepare`: VG exists → activation only.
        let req = FeatureRequest {
            all_features: true,
            ..Default::default()
        };
        let mut ctx = server_ctx(&[]);
        ctx.vg_present = true;
        let mut prompts = FakePrompts::default();
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert_eq!(plan.storage, StoragePlan::Activate);
        assert!(!prompts.calls.contains(&"disk"));
    }

    #[test]
    fn all_features_on_join_node_disables_cluster_scoped_gitops() {
        let req = FeatureRequest {
            all_features: true,
            ..Default::default()
        };
        let mut ctx = server_ctx(&["nvme1n1"]);
        ctx.cluster_init = false;
        let mut prompts = FakePrompts::default();
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert!(plan.tune.enabled);
        assert_eq!(plan.storage, StoragePlan::Prepare("nvme1n1".into()));
        // GitOps is cluster-scoped: not applicable on a join node, never prompted.
        assert!(!plan.gitops.enabled);
        assert!(!plan.gitops.applicable);
    }

    #[test]
    fn storage_is_server_scoped() {
        let req = FeatureRequest {
            storage_disk: Some("nvme1n1".into()),
            ..Default::default()
        };
        let mut ctx = server_ctx(&["nvme1n1"]);
        ctx.server = false; // workstation target
        let mut prompts = FakePrompts::default();
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert_eq!(
            plan.storage,
            StoragePlan::Skip,
            "no LVM on workstation targets"
        );
    }

    #[test]
    fn prompts_run_only_when_undecided_and_interactive() {
        let req = FeatureRequest::default();
        let mut ctx = server_ctx(&[]);
        ctx.interactive = true;
        let mut prompts = FakePrompts::with_answers(true, false);
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert!(plan.tune.enabled);
        assert!(!plan.gitops.enabled);
        assert!(prompts.calls.contains(&"tune"));
        assert!(prompts.calls.contains(&"gitops"));
    }

    #[test]
    fn interactive_storage_prompt_decides_plan() {
        let req = FeatureRequest::default();
        let mut ctx = server_ctx(&["nvme1n1", "nvme2n1"]);
        ctx.interactive = true;
        let mut prompts = FakePrompts {
            storage_answer: StoragePlan::Prepare("nvme2n1".into()),
            ..Default::default()
        };
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert_eq!(plan.storage, StoragePlan::Prepare("nvme2n1".into()));
        assert!(prompts.calls.contains(&"storage"));
    }

    #[test]
    fn prompt_order_matches_execution_order() {
        // Storage runs first in init, so it must be asked first.
        let req = FeatureRequest::default();
        let mut ctx = server_ctx(&["nvme1n1", "nvme2n1"]);
        ctx.interactive = true;
        let mut prompts = FakePrompts {
            storage_answer: StoragePlan::Skip,
            disk_answer: "nvme1n1".into(),
            tune_answer: false,
            gitops_answer: false,
            calls: Vec::new(),
        };
        let _ = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert_eq!(prompts.calls, vec!["storage", "tune", "gitops"]);
    }

    #[test]
    fn explicit_flags_skip_prompts_entirely() {
        let req = FeatureRequest {
            tune_apply: true,
            gitops_bootstrap: true,
            storage_disk: Some("nvme1n1".into()),
            ..Default::default()
        };
        let mut ctx = server_ctx(&["nvme1n1"]);
        ctx.interactive = true;
        let mut prompts = FakePrompts::default();
        let plan = plan_features(&req, &ctx, &mut prompts).unwrap();
        assert!(plan.tune.enabled);
        assert!(plan.gitops.enabled);
        assert_eq!(plan.storage, StoragePlan::Prepare("nvme1n1".into()));
        assert!(
            prompts.calls.is_empty(),
            "flags decide — prompts must not run (got {:?})",
            prompts.calls
        );
    }
}
