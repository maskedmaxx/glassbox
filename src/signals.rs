use crate::docker::SandboxRun;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, Serialize)]
pub struct BehaviorSignals {
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub command_tokens: Vec<String>,
    pub sensitive_paths: Vec<String>,
    pub shell_profiles: Vec<String>,
}

impl BehaviorSignals {
    pub fn from_run(command: &str, run: &SandboxRun) -> Self {
        let text = format!("{command}\n{}\n{}", run.stdout, run.stderr);
        let urls = extract_urls(&text);
        let domains = extract_domains(&urls);
        let command_tokens = extract_command_tokens(&text);
        let sensitive_paths = extract_sensitive_paths(&text, run);
        let shell_profiles = extract_shell_profiles(&text, run);

        Self {
            urls,
            domains,
            command_tokens,
            sensitive_paths,
            shell_profiles,
        }
    }

    pub fn has_command(&self, command: &str) -> bool {
        self.command_tokens.iter().any(|token| token == command)
    }
}

fn extract_urls(text: &str) -> Vec<String> {
    let url_regex = Regex::new(r#"https?://[^\s'"<>)\]]+"#).expect("valid URL regex");
    unique(url_regex.find_iter(text).map(|match_| clean_url(match_.as_str())))
}

fn extract_domains(urls: &[String]) -> Vec<String> {
    unique(urls.iter().filter_map(|url| {
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let host = without_scheme.split('/').next().unwrap_or_default();
        let host = host.rsplit('@').next().unwrap_or(host);
        let host = host.split(':').next().unwrap_or(host);

        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    }))
}

fn extract_command_tokens(text: &str) -> Vec<String> {
    const INTERESTING_COMMANDS: &[&str] = &[
        "apt",
        "bash",
        "cargo",
        "chmod",
        "chown",
        "curl",
        "git",
        "npm",
        "pip",
        "powershell",
        "rm",
        "sh",
        "sudo",
        "tar",
        "wget",
    ];

    let lowered = text.to_ascii_lowercase();

    unique(
        INTERESTING_COMMANDS
            .iter()
            .filter(|command| contains_word(&lowered, command))
            .map(|command| command.to_string()),
    )
}

fn extract_sensitive_paths(text: &str, run: &SandboxRun) -> Vec<String> {
    const SENSITIVE_MARKERS: &[&str] = &[
        ".docker/config.json",
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".ssh",
        "id_ed25519",
        "id_rsa",
        "secret",
        "token",
    ];

    let mut values = BTreeSet::new();
    collect_markers_from_text(text, SENSITIVE_MARKERS, &mut values);
    collect_markers_from_files(run, SENSITIVE_MARKERS, &mut values);
    values.into_iter().collect()
}

fn extract_shell_profiles(text: &str, run: &SandboxRun) -> Vec<String> {
    const PROFILE_MARKERS: &[&str] = &[
        ".bash_profile",
        ".bashrc",
        ".profile",
        ".zprofile",
        ".zshrc",
    ];

    let mut values = BTreeSet::new();
    collect_markers_from_text(text, PROFILE_MARKERS, &mut values);
    collect_markers_from_files(run, PROFILE_MARKERS, &mut values);
    values.into_iter().collect()
}

fn collect_markers_from_text(text: &str, markers: &[&str], values: &mut BTreeSet<String>) {
    let lowered = text.to_ascii_lowercase();

    for marker in markers {
        if lowered.contains(&marker.to_ascii_lowercase()) {
            values.insert((*marker).to_string());
        }
    }
}

fn collect_markers_from_files(run: &SandboxRun, markers: &[&str], values: &mut BTreeSet<String>) {
    for path in run
        .filesystem_diff
        .created
        .iter()
        .map(|entry| entry.path.as_str())
        .chain(
            run.filesystem_diff
                .modified
                .iter()
                .map(|entry| entry.path.as_str()),
        )
        .chain(
            run.filesystem_diff
                .deleted
                .iter()
                .map(|entry| entry.path.as_str()),
        )
    {
        let lowered = path.to_ascii_lowercase();

        for marker in markers {
            if lowered.contains(&marker.to_ascii_lowercase()) {
                values.insert(path.to_string());
            }
        }
    }
}

fn contains_word(text: &str, word: &str) -> bool {
    let word_regex =
        Regex::new(&format!(r"(^|[^a-z0-9_-]){}([^a-z0-9_-]|$)", regex::escape(word)))
            .expect("valid word regex");
    word_regex.is_match(text)
}

fn clean_url(url: &str) -> String {
    url.trim_end_matches(|char| matches!(char, '.' | ',' | ';' | ':'))
        .to_string()
}

fn unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::BehaviorSignals;
    use crate::docker::SandboxRun;
    use crate::fsdiff::{FileEntry, FilesystemDiff, ModifiedFile};
    use std::time::Duration;

    #[test]
    fn extracts_urls_domains_commands_and_paths() {
        let run = SandboxRun {
            exit_code: Some(0),
            stdout: "downloaded https://example.com/install.sh with curl".to_string(),
            stderr: String::new(),
            duration: Duration::from_millis(10),
            filesystem_diff: FilesystemDiff {
                created: vec![entry("/root/.ssh/config")],
                modified: vec![ModifiedFile {
                    path: "/root/.bashrc".to_string(),
                    before_size: 1,
                    after_size: 2,
                    before_mode: "644".to_string(),
                    after_mode: "644".to_string(),
                }],
                deleted: vec![],
            },
        };

        let signals = BehaviorSignals::from_run("bash install.sh", &run);

        assert_eq!(signals.urls, vec!["https://example.com/install.sh".to_string()]);
        assert_eq!(signals.domains, vec!["example.com".to_string()]);
        assert!(signals.has_command("bash"));
        assert!(signals.has_command("curl"));
        assert_eq!(signals.sensitive_paths, vec!["/root/.ssh/config".to_string()]);
        assert_eq!(signals.shell_profiles, vec!["/root/.bashrc".to_string()]);
    }

    fn entry(path: &str) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            size: 1,
            modified_at: "1".to_string(),
            mode: "644".to_string(),
            kind: "f".to_string(),
        }
    }
}
