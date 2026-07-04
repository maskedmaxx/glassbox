use crate::docker::SandboxRun;
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
    pub fn evaluate(&self, run: &SandboxRun) -> Vec<Finding> {
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

        findings
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let haystack = haystack.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| haystack.contains(&needle.to_ascii_lowercase()))
}
