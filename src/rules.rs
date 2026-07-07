use crate::docker::SandboxRun;
use crate::signals::BehaviorSignals;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct RuleEngine;

impl RuleEngine {
    pub fn evaluate(&self, run: &SandboxRun, signals: &BehaviorSignals) -> Vec<Finding> {
        let combined = format!("{}\n{}", run.stdout, run.stderr);
        let mut findings = Vec::new();

        if combined.contains("sudo") {
            findings.push(Finding {
                severity: Severity::High,
                title: "Privilege escalation signal".to_string(),
                detail: "Command output referenced sudo.".to_string(),
            });
        }

        if contains_any(&combined, &[".bashrc", ".zshrc", ".profile", "PATH="]) {
            findings.push(Finding {
                severity: Severity::Medium,
                title: "Shell profile signal".to_string(),
                detail: "Command output referenced shell profile or PATH changes.".to_string(),
            });
        }

        if contains_any(&combined, &["ssh", "id_rsa", ".ssh"]) {
            findings.push(Finding {
                severity: Severity::High,
                title: "SSH-related signal".to_string(),
                detail: "Command output referenced SSH-related paths or commands.".to_string(),
            });
        }

        if contains_any(&combined, &["curl", "wget", "download"]) {
            findings.push(Finding {
                severity: Severity::Low,
                title: "Download signal".to_string(),
                detail: "Command output referenced a download tool or download action.".to_string(),
            });
        }

        if signals.has_command("sudo") {
            findings.push(Finding {
                severity: Severity::High,
                title: "Privilege escalation command".to_string(),
                detail: "The command or output referenced sudo.".to_string(),
            });
        }

        if signals.has_command("rm") {
            findings.push(Finding {
                severity: Severity::Medium,
                title: "Deletion command".to_string(),
                detail: "The command or output referenced rm.".to_string(),
            });
        }

        if !signals.domains.is_empty() {
            findings.push(Finding {
                severity: Severity::Low,
                title: "Network destination signal".to_string(),
                detail: format!(
                    "Detected URL domains: {}.",
                    signals.domains.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                ),
            });
        }

        for path in &signals.sensitive_paths {
            findings.push(Finding {
                severity: Severity::High,
                title: "Sensitive path signal".to_string(),
                detail: format!("Detected sensitive path marker `{path}`."),
            });
        }

        for path in &signals.shell_profiles {
            findings.push(Finding {
                severity: Severity::Medium,
                title: "Shell profile signal".to_string(),
                detail: format!("Detected shell profile marker `{path}`."),
            });
        }

        for entry in run
            .filesystem_diff
            .created
            .iter()
            .chain(run.filesystem_diff.deleted.iter())
        {
            if is_sensitive_path(&entry.path) {
                findings.push(Finding {
                    severity: Severity::High,
                    title: "Sensitive file path touched".to_string(),
                    detail: format!("Filesystem diff includes `{}`.", entry.path),
                });
            }

            if is_shell_profile(&entry.path) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    title: "Shell profile changed".to_string(),
                    detail: format!("Filesystem diff includes `{}`.", entry.path),
                });
            }
        }

        for entry in &run.filesystem_diff.modified {
            if is_sensitive_path(&entry.path) {
                findings.push(Finding {
                    severity: Severity::High,
                    title: "Sensitive file path modified".to_string(),
                    detail: format!("Filesystem diff includes `{}`.", entry.path),
                });
            }

            if is_shell_profile(&entry.path) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    title: "Shell profile modified".to_string(),
                    detail: format!("Filesystem diff includes `{}`.", entry.path),
                });
            }
        }

        findings
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let haystack = haystack.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| haystack.contains(&needle.to_ascii_lowercase()))
}

fn is_sensitive_path(path: &str) -> bool {
    contains_any(
        path,
        &[
            "/.ssh/",
            "id_rsa",
            "id_ed25519",
            ".npmrc",
            ".pypirc",
            ".netrc",
            "token",
            "secret",
        ],
    )
}

fn is_shell_profile(path: &str) -> bool {
    path.ends_with("/.bashrc")
        || path.ends_with("/.zshrc")
        || path.ends_with("/.profile")
        || path.ends_with("/.bash_profile")
}
