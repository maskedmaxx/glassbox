use crate::contract::BehaviorSnapshot;
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub max_risk: Option<String>,
    pub allow: CapabilityRules,
    pub deny: DenyRules,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CapabilityRules {
    pub domains: Vec<String>,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub exec: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DenyRules {
    pub domains: Vec<String>,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub exec: Vec<String>,
    pub privilege_escalation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyViolation {
    pub category: String,
    pub value: String,
    pub reason: String,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy {}", path.display()))?;
        serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse YAML policy {}", path.display()))
    }

    pub fn evaluate(&self, snapshot: &BehaviorSnapshot, risk: &str) -> Vec<PolicyViolation> {
        let mut violations = BTreeSet::new();

        evaluate_category(
            "domain",
            &snapshot.domains,
            &self.allow.domains,
            &self.deny.domains,
            &mut violations,
        );
        evaluate_category(
            "read",
            &snapshot.read_paths,
            &self.allow.reads,
            &self.deny.reads,
            &mut violations,
        );

        let writes = unique(
            snapshot
                .created_paths
                .iter()
                .chain(snapshot.modified_paths.iter())
                .chain(snapshot.deleted_paths.iter())
                .cloned(),
        );
        evaluate_category(
            "write",
            &writes,
            &self.allow.writes,
            &self.deny.writes,
            &mut violations,
        );

        // `commands` comes from periodic `ps` sampling and is intentionally
        // excluded from policy enforcement because short-lived processes can
        // appear or disappear between runs. `executed_programs` comes from
        // strace execve observations and is the authoritative exec capability.
        let executables = unique(snapshot.executed_programs.iter().cloned());
        evaluate_category(
            "exec",
            &executables,
            &self.allow.exec,
            &self.deny.exec,
            &mut violations,
        );

        if self.deny.privilege_escalation
            && executables
                .iter()
                .any(|value| command_name(value) == "sudo")
        {
            violations.insert(PolicyViolation {
                category: "privilege".to_string(),
                value: "sudo".to_string(),
                reason: "privilege escalation is denied by policy".to_string(),
            });
        }

        if let Some(max_risk) = &self.max_risk {
            if risk_rank(risk) > risk_rank(max_risk) {
                violations.insert(PolicyViolation {
                    category: "risk".to_string(),
                    value: risk.to_string(),
                    reason: format!("risk exceeds policy maximum `{max_risk}`"),
                });
            }
        }

        violations.into_iter().collect()
    }
}

fn evaluate_category(
    category: &str,
    values: &[String],
    allow: &[String],
    deny: &[String],
    violations: &mut BTreeSet<PolicyViolation>,
) {
    for value in values {
        if deny.iter().any(|pattern| glob_matches(pattern, value)) {
            violations.insert(PolicyViolation {
                category: category.to_string(),
                value: value.clone(),
                reason: "matches deny rule".to_string(),
            });
            continue;
        }

        if !allow.is_empty() && !allow.iter().any(|pattern| glob_matches(pattern, value)) {
            violations.insert(PolicyViolation {
                category: category.to_string(),
                value: value.clone(),
                reason: "not matched by any allow rule".to_string(),
            });
        }
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                regex.push_str(".*");
            }
            '*' => regex.push_str("[^/]*"),
            '?' => regex.push('.'),
            _ => regex.push_str(&regex::escape(&ch.to_string())),
        }
    }

    regex.push('$');
    Regex::new(&regex)
        .expect("generated policy glob regex should be valid")
        .is_match(value)
}

fn unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn command_name(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

fn risk_rank(risk: &str) -> u8 {
    match risk.to_ascii_lowercase().as_str() {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{glob_matches, Policy};
    use crate::contract::BehaviorSnapshot;

    #[test]
    fn glob_supports_double_star_paths_and_domain_wildcards() {
        assert!(glob_matches("$HOME/.ssh/**", "$HOME/.ssh/id_rsa"));
        assert!(glob_matches(
            "*.githubusercontent.com",
            "objects.githubusercontent.com"
        ));
        assert!(!glob_matches("github.com", "evilgithub.com"));
    }

    #[test]
    fn sampled_processes_do_not_trigger_exec_policy() {
        let policy: Policy = serde_yaml::from_str(
            r#"
deny:
  exec:
    - "uname"
"#,
        )
        .unwrap();

        let snapshot = BehaviorSnapshot {
            commands: vec!["uname".to_string()],
            ..BehaviorSnapshot::default()
        };

        assert!(policy.evaluate(&snapshot, "low").is_empty());
    }

    #[test]
    fn deny_rules_catch_sensitive_reads() {
        let policy: Policy = serde_yaml::from_str(
            r#"
deny:
  reads:
    - "$HOME/.ssh/**"
  privilege_escalation: true
"#,
        )
        .unwrap();

        let snapshot = BehaviorSnapshot {
            read_paths: vec!["$HOME/.ssh/id_rsa".to_string()],
            executed_programs: vec!["/usr/bin/sudo".to_string()],
            ..BehaviorSnapshot::default()
        };

        let violations = policy.evaluate(&snapshot, "low");

        assert!(violations.iter().any(|item| item.category == "read"));
        assert!(violations.iter().any(|item| item.category == "privilege"));
    }
}
