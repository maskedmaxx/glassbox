use crate::docker::{DockerRunner, SandboxRun};
use crate::installer::{self, InstallerMetadata};
use crate::policy::{Policy, PolicyViolation};
use crate::report::AuditReport;
use crate::rules::RuleEngine;
use crate::signals::BehaviourSignals;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const LOCK_SCHEMA_VERSION: u32 = 1;
const NETWORK_PEER_CATEGORY: &str = "network_peer";
const PROCESS_SAMPLE_CATEGORY: &str = "process_sample";

#[derive(Debug, Clone)]
pub struct LockOptions {
    pub name: String,
    pub command: String,
    pub image: String,
    pub out_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub lockfile: PathBuf,
    pub command: Option<String>,
    pub image: Option<String>,
    pub policy: Option<PathBuf>,
    pub strict_network: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorLock {
    pub schema_version: u32,
    pub name: String,
    pub command: String,
    pub image: String,
    pub risk: String,
    #[serde(default)]
    pub installer: Option<InstallerMetadata>,
    pub behavior: BehaviorSnapshot,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BehaviorSnapshot {
    pub domains: Vec<String>,
    pub commands: Vec<String>,
    pub executed_programs: Vec<String>,
    pub read_paths: Vec<String>,
    pub created_paths: Vec<String>,
    pub modified_paths: Vec<String>,
    pub deleted_paths: Vec<String>,
    pub sensitive_paths: Vec<String>,
    pub shell_profiles: Vec<String>,
    pub network_peers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftItem {
    pub category: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BehaviorDrift {
    pub added: Vec<DriftItem>,
    pub removed: Vec<DriftItem>,
    pub previous_risk: String,
    pub current_risk: String,
    pub previous_installer_sha256: Option<String>,
    pub current_installer_sha256: Option<String>,
}

impl BehaviorLock {
    fn from_report(
        name: String,
        report: &AuditReport,
        installer: Option<InstallerMetadata>,
    ) -> Self {
        Self {
            schema_version: LOCK_SCHEMA_VERSION,
            name,
            command: report.command.clone(),
            image: report.image.clone(),
            risk: report.risk_label().to_string(),
            installer,
            behavior: BehaviorSnapshot::from_report(report),
        }
    }
}

impl BehaviorSnapshot {
    fn from_report(report: &AuditReport) -> Self {
        let read_paths = report
            .trace_summary
            .opened_files
            .iter()
            .map(|access| normalize_path(&access.path))
            .filter(|path| should_track_read(path));

        Self {
            domains: normalized(report.signals.domains.clone()),
            commands: normalized(report.process_summary.commands()),
            executed_programs: normalized(
                report
                    .trace_summary
                    .executed
                    .iter()
                    .map(|program| program.path.clone()),
            ),
            read_paths: normalized(read_paths),
            created_paths: normalized_paths(
                report
                    .filesystem_diff
                    .created
                    .iter()
                    .map(|entry| entry.path.as_str()),
            ),
            modified_paths: normalized_paths(
                report
                    .filesystem_diff
                    .modified
                    .iter()
                    .map(|entry| entry.path.as_str()),
            ),
            deleted_paths: normalized_paths(
                report
                    .filesystem_diff
                    .deleted
                    .iter()
                    .map(|entry| entry.path.as_str()),
            ),
            sensitive_paths: normalized_paths(
                report.signals.sensitive_paths.iter().map(String::as_str),
            ),
            shell_profiles: normalized_paths(
                report.signals.shell_profiles.iter().map(String::as_str),
            ),
            network_peers: normalized(report.network_summary.peer_addresses()),
        }
    }
}

impl BehaviorDrift {
    fn between(expected: &BehaviorLock, current: &BehaviorLock) -> Self {
        let mut added = Vec::new();
        let mut removed = Vec::new();

        compare_values(
            "domain",
            &expected.behavior.domains,
            &current.behavior.domains,
            &mut added,
            &mut removed,
        );
        compare_values(
            PROCESS_SAMPLE_CATEGORY,
            &expected.behavior.commands,
            &current.behavior.commands,
            &mut added,
            &mut removed,
        );
        compare_values(
            "exec",
            &expected.behavior.executed_programs,
            &current.behavior.executed_programs,
            &mut added,
            &mut removed,
        );
        compare_values(
            "read_path",
            &expected.behavior.read_paths,
            &current.behavior.read_paths,
            &mut added,
            &mut removed,
        );
        compare_values(
            "created_path",
            &expected.behavior.created_paths,
            &current.behavior.created_paths,
            &mut added,
            &mut removed,
        );
        compare_values(
            "modified_path",
            &expected.behavior.modified_paths,
            &current.behavior.modified_paths,
            &mut added,
            &mut removed,
        );
        compare_values(
            "deleted_path",
            &expected.behavior.deleted_paths,
            &current.behavior.deleted_paths,
            &mut added,
            &mut removed,
        );
        compare_values(
            "sensitive_path",
            &expected.behavior.sensitive_paths,
            &current.behavior.sensitive_paths,
            &mut added,
            &mut removed,
        );
        compare_values(
            "shell_profile",
            &expected.behavior.shell_profiles,
            &current.behavior.shell_profiles,
            &mut added,
            &mut removed,
        );
        compare_values(
            NETWORK_PEER_CATEGORY,
            &expected.behavior.network_peers,
            &current.behavior.network_peers,
            &mut added,
            &mut removed,
        );

        Self {
            added,
            removed,
            previous_risk: expected.risk.clone(),
            current_risk: current.risk.clone(),
            previous_installer_sha256: installer_sha256(expected),
            current_installer_sha256: installer_sha256(current),
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.added.is_empty()
            || !self.removed.is_empty()
            || self.previous_risk != self.current_risk
            || self.previous_installer_sha256 != self.current_installer_sha256
    }

    pub fn has_blocking_changes(&self, strict_network: bool) -> bool {
        let new_capability = self
            .added
            .iter()
            .any(|item| is_blocking_category(item.category, strict_network));

        new_capability || risk_rank(&self.current_risk) > risk_rank(&self.previous_risk)
    }
}

pub fn create_lock(options: LockOptions) -> Result<PathBuf> {
    println!("Glassbox behavioral lock starting");
    println!("Command: {}", options.command);
    println!("Image: {}", options.image);

    let (report, installer) = collect_report(options.command, options.image)?;
    let lock = BehaviorLock::from_report(options.name.clone(), &report, installer);

    fs::create_dir_all(&options.out_dir).with_context(|| {
        format!(
            "failed to create lockfile output directory {}",
            options.out_dir.display()
        )
    })?;

    let path = options
        .out_dir
        .join(format!("{}.glassbox.lock.json", safe_name(&options.name)));
    let json = serde_json::to_string_pretty(&lock).context("failed to serialize lockfile")?;
    fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;

    println!();
    println!("Behavior locked: {}", path.display());
    println!("Risk: {}", lock.risk);

    if let Some(installer) = &lock.installer {
        print_installer(installer);
    }

    println!("Domains: {}", lock.behavior.domains.len());
    println!("Reads tracked: {}", lock.behavior.read_paths.len());
    println!("Process samples: {}", lock.behavior.commands.len());
    println!(
        "Filesystem paths: {}",
        lock.behavior.created_paths.len()
            + lock.behavior.modified_paths.len()
            + lock.behavior.deleted_paths.len()
    );

    Ok(path)
}

pub fn diff_lock(options: CheckOptions) -> Result<BehaviorDrift> {
    let (expected, current) = run_against_lock(&options)?;
    let drift = BehaviorDrift::between(&expected, &current);
    print_drift(&drift, options.strict_network, options.verbose);

    let violations = evaluate_policy(options.policy.as_deref(), &current)?;
    print_policy_violations(&violations);

    Ok(drift)
}

pub fn verify_lock(options: CheckOptions) -> Result<()> {
    let (expected, current) = run_against_lock(&options)?;
    let drift = BehaviorDrift::between(&expected, &current);
    print_drift(&drift, options.strict_network, options.verbose);

    let violations = evaluate_policy(options.policy.as_deref(), &current)?;
    print_policy_violations(&violations);

    if !violations.is_empty() {
        bail!(
            "behavior verification failed: {} policy violation(s) detected",
            violations.len()
        );
    }

    if drift.has_blocking_changes(options.strict_network) {
        bail!("behavior verification failed: new capabilities or risk escalation detected");
    }

    if drift.has_changes() {
        println!("Verification passed: only non-blocking behavior changed.");
    } else {
        println!("Verification passed: behavior matches the lockfile.");
    }

    Ok(())
}

fn run_against_lock(options: &CheckOptions) -> Result<(BehaviorLock, BehaviorLock)> {
    let expected = read_lock(&options.lockfile)?;
    let command = options
        .command
        .clone()
        .unwrap_or_else(|| expected.command.clone());
    let image = options
        .image
        .clone()
        .unwrap_or_else(|| expected.image.clone());

    println!("Glassbox behavior check");
    println!("Lockfile: {}", options.lockfile.display());
    println!("Command: {command}");
    println!("Image: {image}");
    println!();

    let (report, installer) = collect_report(command, image)?;
    let current = BehaviorLock::from_report(expected.name.clone(), &report, installer);

    Ok((expected, current))
}

fn collect_report(
    command: String,
    image: String,
) -> Result<(AuditReport, Option<InstallerMetadata>)> {
    let runner = DockerRunner::new(image.clone());
    let frozen = installer::freeze_if_supported(&command, &runner)?;

    let sandbox_run: SandboxRun = if let Some(frozen) = &frozen {
        println!();
        println!("Installer freezing enabled");
        print_installer(&frozen.metadata);
        println!("Executing the exact captured bytes inside the audit sandbox.");
        runner
            .run_script_bytes(&frozen.bytes, &frozen.metadata.shell)
            .context("sandbox execution of frozen installer failed")?
    } else {
        runner.run(&command).context("sandbox execution failed")?
    };

    let signals = BehaviourSignals::from_run(&command, &sandbox_run);
    let findings = RuleEngine.evaluate(&sandbox_run, &signals);
    let report = AuditReport::from_run(command, image, sandbox_run, signals, findings);
    let metadata = frozen.map(|frozen| frozen.metadata);

    Ok((report, metadata))
}

fn evaluate_policy(path: Option<&Path>, lock: &BehaviorLock) -> Result<Vec<PolicyViolation>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };

    let policy = Policy::load(path)?;
    Ok(policy.evaluate(&lock.behavior, &lock.risk))
}

fn read_lock(path: &Path) -> Result<BehaviorLock> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read lockfile {}", path.display()))?;
    let mut lock: BehaviorLock = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse lockfile {}", path.display()))?;

    if lock.schema_version != LOCK_SCHEMA_VERSION {
        bail!(
            "unsupported lockfile schema version {} (expected {})",
            lock.schema_version,
            LOCK_SCHEMA_VERSION
        );
    }

    normalize_snapshot_paths(&mut lock.behavior);
    Ok(lock)
}

fn normalize_snapshot_paths(snapshot: &mut BehaviorSnapshot) {
    snapshot.read_paths = normalized(snapshot.read_paths.iter().map(|path| normalize_path(path)));
    snapshot.created_paths = normalized(
        snapshot
            .created_paths
            .iter()
            .map(|path| normalize_path(path)),
    );
    snapshot.modified_paths = normalized(
        snapshot
            .modified_paths
            .iter()
            .map(|path| normalize_path(path)),
    );
    snapshot.deleted_paths = normalized(
        snapshot
            .deleted_paths
            .iter()
            .map(|path| normalize_path(path)),
    );
    snapshot.sensitive_paths = normalized(
        snapshot
            .sensitive_paths
            .iter()
            .map(|path| normalize_path(path)),
    );
    snapshot.shell_profiles = normalized(
        snapshot
            .shell_profiles
            .iter()
            .map(|path| normalize_path(path)),
    );
}

fn print_installer(installer: &InstallerMetadata) {
    println!("Frozen installer:");
    println!("  source:   {}", installer.source_url);
    println!("  resolved: {}", installer.resolved_url);
    println!("  sha256:   {}", installer.sha256);
    println!("  size:     {} bytes", installer.size_bytes);
}

fn print_drift(drift: &BehaviorDrift, strict_network: bool, verbose: bool) {
    if !drift.has_changes() {
        println!("Stable behavior: no changes detected.");
        return;
    }

    let blocking_additions: Vec<&DriftItem> = drift
        .added
        .iter()
        .filter(|item| is_blocking_category(item.category, strict_network))
        .collect();
    let informational_additions: Vec<&DriftItem> = drift
        .added
        .iter()
        .filter(|item| !is_blocking_category(item.category, strict_network))
        .collect();
    let risk_escalated = risk_rank(&drift.current_risk) > risk_rank(&drift.previous_risk);
    let blocking = !blocking_additions.is_empty() || risk_escalated;

    if blocking {
        println!("BEHAVIORAL DRIFT DETECTED");
        println!();
        println!("Blocking changes");

        for item in &blocking_additions {
            println!("  + {:<16} {}", item.category, item.value);
        }

        if risk_escalated {
            println!(
                "  ~ {:<16} {} -> {}",
                "risk", drift.previous_risk, drift.current_risk
            );
        }
    } else {
        println!("Behavioral observations changed");
        println!();
        println!("Blocking drift");
        println!("  none");
    }

    let has_informational = !informational_additions.is_empty()
        || !drift.removed.is_empty()
        || (!risk_escalated && drift.previous_risk != drift.current_risk)
        || drift.previous_installer_sha256 != drift.current_installer_sha256;

    if !has_informational {
        return;
    }

    println!();
    println!("Informational changes");

    if verbose {
        for item in &informational_additions {
            println!(
                "  + {:<16} {}{}",
                item.category,
                item.value,
                informational_note(item.category, strict_network)
            );
        }

        for item in &drift.removed {
            println!(
                "  - {:<16} {}{}",
                item.category,
                item.value,
                removal_note(item.category)
            );
        }

        if !risk_escalated && drift.previous_risk != drift.current_risk {
            println!(
                "  ~ {:<16} {} -> {}",
                "risk", drift.previous_risk, drift.current_risk
            );
        }

        if drift.previous_installer_sha256 != drift.current_installer_sha256 {
            println!(
                "  ~ {:<16} {} -> {}",
                "installer_sha256",
                short_hash(drift.previous_installer_sha256.as_deref()),
                short_hash(drift.current_installer_sha256.as_deref())
            );
        }

        return;
    }

    print_informational_summary(
        drift,
        &informational_additions,
        strict_network,
        risk_escalated,
    );
    println!("  use --verbose to show individual informational observations");
}

fn print_informational_summary(
    drift: &BehaviorDrift,
    informational_additions: &[&DriftItem],
    strict_network: bool,
    risk_escalated: bool,
) {
    let process_added = informational_additions
        .iter()
        .filter(|item| item.category == PROCESS_SAMPLE_CATEGORY)
        .count();
    let process_removed = drift
        .removed
        .iter()
        .filter(|item| item.category == PROCESS_SAMPLE_CATEGORY)
        .count();

    if process_added > 0 || process_removed > 0 {
        println!("  process samples: +{process_added} / -{process_removed}");
    }

    let peer_added = informational_additions
        .iter()
        .filter(|item| item.category == NETWORK_PEER_CATEGORY)
        .count();
    let peer_removed = drift
        .removed
        .iter()
        .filter(|item| item.category == NETWORK_PEER_CATEGORY)
        .count();

    if peer_added > 0 || peer_removed > 0 {
        let suffix = if strict_network {
            " (removed peers are non-blocking)"
        } else {
            ""
        };
        println!("  network peers:   +{peer_added} / -{peer_removed}{suffix}");
    }

    let other_removed = drift
        .removed
        .iter()
        .filter(|item| {
            item.category != PROCESS_SAMPLE_CATEGORY && item.category != NETWORK_PEER_CATEGORY
        })
        .count();

    if other_removed > 0 {
        println!("  capabilities removed: {other_removed}");
    }

    if !risk_escalated && drift.previous_risk != drift.current_risk {
        println!(
            "  risk changed: {} -> {}",
            drift.previous_risk, drift.current_risk
        );
    }

    if drift.previous_installer_sha256 != drift.current_installer_sha256 {
        println!(
            "  installer sha256: {} -> {}",
            short_hash(drift.previous_installer_sha256.as_deref()),
            short_hash(drift.current_installer_sha256.as_deref())
        );
    }
}

fn informational_note(category: &str, strict_network: bool) -> &'static str {
    match category {
        PROCESS_SAMPLE_CATEGORY => " (process sampling can vary)",
        NETWORK_PEER_CATEGORY if !strict_network => " (destination IP can vary)",
        _ => "",
    }
}

fn removal_note(category: &str) -> &'static str {
    match category {
        PROCESS_SAMPLE_CATEGORY => " (process sampling can vary)",
        NETWORK_PEER_CATEGORY => " (destination IP can vary)",
        _ => " (removed capability; non-blocking)",
    }
}

fn is_blocking_category(category: &str, strict_network: bool) -> bool {
    match category {
        PROCESS_SAMPLE_CATEGORY => false,
        NETWORK_PEER_CATEGORY => strict_network,
        _ => true,
    }
}

fn print_policy_violations(violations: &[PolicyViolation]) {
    if violations.is_empty() {
        return;
    }

    println!();
    println!("Policy violations");

    for violation in violations {
        println!(
            "! {:<12} {} ({})",
            violation.category, violation.value, violation.reason
        );
    }
}

fn compare_values(
    category: &'static str,
    expected: &[String],
    current: &[String],
    added: &mut Vec<DriftItem>,
    removed: &mut Vec<DriftItem>,
) {
    let expected: BTreeSet<&str> = expected.iter().map(String::as_str).collect();
    let current: BTreeSet<&str> = current.iter().map(String::as_str).collect();

    added.extend(current.difference(&expected).map(|value| DriftItem {
        category,
        value: (*value).to_string(),
    }));
    removed.extend(expected.difference(&current).map(|value| DriftItem {
        category,
        value: (*value).to_string(),
    }));
}

fn normalized(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_paths<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    normalized(values.into_iter().map(normalize_path))
}

fn normalize_path(path: &str) -> String {
    let path = path.replace('\\', "/");

    if path == "/root" {
        return "$HOME".to_string();
    }

    if let Some(rest) = path.strip_prefix("/root/") {
        return format!("$HOME/{rest}");
    }

    if path == "/workspace" {
        return "$WORKSPACE".to_string();
    }

    if let Some(rest) = path.strip_prefix("/workspace/") {
        return format!("$WORKSPACE/{rest}");
    }

    if let Some(rest) = path.strip_prefix("/home/") {
        if let Some((_, tail)) = rest.split_once('/') {
            return format!("$HOME/{tail}");
        }

        return "$HOME".to_string();
    }

    if path == "/tmp"
        || path.starts_with("/tmp/")
        || path == "/var/tmp"
        || path.starts_with("/var/tmp/")
    {
        return "$TMP/**".to_string();
    }

    path
}

fn should_track_read(path: &str) -> bool {
    path == "$HOME"
        || path.starts_with("$HOME/")
        || path == "$WORKSPACE"
        || path.starts_with("$WORKSPACE/")
        || matches!(
            path,
            "/etc/hosts" | "/etc/os-release" | "/etc/passwd" | "/etc/shadow" | "/etc/sudoers"
        )
}

fn installer_sha256(lock: &BehaviorLock) -> Option<String> {
    lock.installer
        .as_ref()
        .map(|installer| installer.sha256.clone())
}

fn short_hash(hash: Option<&str>) -> String {
    match hash {
        Some(hash) => hash.chars().take(12).collect(),
        None => "none".to_string(),
    }
}

fn safe_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('-');

    if sanitized.is_empty() {
        "glassbox".to_string()
    } else {
        sanitized.to_string()
    }
}

fn risk_rank(risk: &str) -> u8 {
    match risk {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_path, BehaviorDrift, BehaviorLock, BehaviorSnapshot, LOCK_SCHEMA_VERSION,
    };

    #[test]
    fn detects_new_capabilities() {
        let expected = lock(
            snapshot(&["example.com"], &["$HOME/.tool/bin/tool"], &[]),
            "low",
        );
        let current = lock(
            snapshot(
                &["example.com", "telemetry.example"],
                &["$HOME/.tool/bin/tool"],
                &["$HOME/.ssh/id_rsa"],
            ),
            "high",
        );

        let drift = BehaviorDrift::between(&expected, &current);

        assert!(drift
            .added
            .iter()
            .any(|item| item.category == "domain" && item.value == "telemetry.example"));
        assert!(drift
            .added
            .iter()
            .any(|item| item.category == "sensitive_path"));
        assert!(drift.has_blocking_changes(false));
    }

    #[test]
    fn network_peer_changes_are_non_blocking_by_default() {
        let before = BehaviorSnapshot {
            network_peers: vec!["1.1.1.1:443".to_string()],
            ..BehaviorSnapshot::default()
        };
        let mut after = before.clone();
        after.network_peers = vec!["1.0.0.1:443".to_string()];

        let drift = BehaviorDrift::between(&lock(before, "low"), &lock(after, "low"));

        assert!(drift.has_changes());
        assert!(!drift.has_blocking_changes(false));
        assert!(drift.has_blocking_changes(true));
    }

    #[test]
    fn process_samples_are_informational() {
        let before = BehaviorSnapshot {
            commands: vec!["uname".to_string()],
            ..BehaviorSnapshot::default()
        };
        let after = BehaviorSnapshot {
            commands: vec!["head".to_string(), "mesg".to_string()],
            ..BehaviorSnapshot::default()
        };

        let drift = BehaviorDrift::between(&lock(before, "low"), &lock(after, "low"));

        assert!(drift.has_changes());
        assert!(drift
            .added
            .iter()
            .all(|item| item.category == "process_sample"));
        assert!(!drift.has_blocking_changes(false));
        assert!(!drift.has_blocking_changes(true));
    }

    #[test]
    fn normalizes_container_specific_paths() {
        assert_eq!(normalize_path("/root/.bashrc"), "$HOME/.bashrc");
        assert_eq!(
            normalize_path("/home/alice/.config/tool"),
            "$HOME/.config/tool"
        );
        assert_eq!(normalize_path("/workspace/project"), "$WORKSPACE/project");
        assert_eq!(normalize_path("/tmp/random-123"), "$TMP/**");
    }

    fn lock(behavior: BehaviorSnapshot, risk: &str) -> BehaviorLock {
        BehaviorLock {
            schema_version: LOCK_SCHEMA_VERSION,
            name: "test".to_string(),
            command: "echo test".to_string(),
            image: "glassbox-audit:latest".to_string(),
            risk: risk.to_string(),
            installer: None,
            behavior,
        }
    }

    fn snapshot(domains: &[&str], created: &[&str], sensitive: &[&str]) -> BehaviorSnapshot {
        BehaviorSnapshot {
            domains: domains.iter().map(|value| (*value).to_string()).collect(),
            created_paths: created.iter().map(|value| (*value).to_string()).collect(),
            sensitive_paths: sensitive.iter().map(|value| (*value).to_string()).collect(),
            ..BehaviorSnapshot::default()
        }
    }
}
