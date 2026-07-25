use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExecutedProgram {
    pub path: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TraceFileAccess {
    pub syscall: String,
    pub path: String,
    pub flags: Option<String>,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TraceFileMutation {
    pub syscall: String,
    pub path: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TraceNetworkConnect {
    pub address: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TraceSummary {
    pub executed: Vec<ExecutedProgram>,
    pub opened_files: Vec<TraceFileAccess>,
    pub file_mutations: Vec<TraceFileMutation>,
    pub network_connects: Vec<TraceNetworkConnect>,
}

impl TraceSummary {
    pub fn from_log_dir(dir: &Path, prefix: &str) -> Result<Self> {
        let mut summary = Self::default();

        for entry in fs::read_dir(dir)
            .with_context(|| format!("failed to read trace directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            if name == prefix || name.starts_with(&format!("{prefix}.")) {
                summary.merge_file(&path)?;
            }
        }

        summary.sort_and_dedup();
        Ok(summary)
    }

    pub fn count(&self) -> usize {
        self.executed.len()
            + self.opened_files.len()
            + self.file_mutations.len()
            + self.network_connects.len()
    }

    pub fn saw_path_containing(&self, marker: &str) -> bool {
        self.opened_files
            .iter()
            .any(|access| access.path.contains(marker))
            || self
                .file_mutations
                .iter()
                .any(|mutation| mutation.path.contains(marker))
    }

    fn merge_file(&mut self, path: &Path) -> Result<()> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read trace log {}", path.display()))?;

        for line in contents.lines() {
            if let Some(program) = parse_execve(line) {
                self.executed.push(program);
            }

            if let Some(access) = parse_file_access(line) {
                self.opened_files.push(access);
            }

            if let Some(mutation) = parse_file_mutation(line) {
                self.file_mutations.push(mutation);
            }

            if let Some(connect) = parse_network_connect(line) {
                self.network_connects.push(connect);
            }
        }

        Ok(())
    }

    fn sort_and_dedup(&mut self) {
        self.executed = dedup(std::mem::take(&mut self.executed));
        self.opened_files = dedup(std::mem::take(&mut self.opened_files));
        self.file_mutations = dedup(std::mem::take(&mut self.file_mutations));
        self.network_connects = dedup(std::mem::take(&mut self.network_connects));
    }
}

fn parse_execve(line: &str) -> Option<ExecutedProgram> {
    if !line.contains("execve(") {
        return None;
    }

    let quoted = quoted_strings(line);
    let path = quoted.first()?.clone();

    if is_internal_path(&path) {
        return None;
    }

    let args = parse_exec_args(line).unwrap_or_default();

    Some(ExecutedProgram { path, args })
}

fn parse_file_access(line: &str) -> Option<TraceFileAccess> {
    let syscall = syscall_name(line)?;

    if !matches!(
        syscall.as_str(),
        "open" | "openat" | "openat2" | "access" | "stat" | "newfstatat"
    ) {
        return None;
    }

    let quoted = quoted_strings(line);
    let path = quoted.into_iter().find(|value| value.starts_with('/'))?;

    if is_internal_path(&path) {
        return None;
    }

    Some(TraceFileAccess {
        syscall,
        path,
        flags: parse_open_flags(line),
    })
}

fn parse_file_mutation(line: &str) -> Option<TraceFileMutation> {
    let syscall = syscall_name(line)?;

    if !matches!(
        syscall.as_str(),
        "chmod"
            | "fchmodat"
            | "chown"
            | "fchownat"
            | "mkdir"
            | "mkdirat"
            | "rename"
            | "renameat"
            | "renameat2"
            | "rmdir"
            | "unlink"
            | "unlinkat"
    ) {
        return None;
    }

    let quoted = quoted_strings(line);
    let path = quoted.into_iter().find(|value| value.starts_with('/'))?;

    if is_internal_path(&path) {
        return None;
    }

    Some(TraceFileMutation {
        syscall,
        path,
        detail: parse_result(line),
    })
}

fn parse_network_connect(line: &str) -> Option<TraceNetworkConnect> {
    if !line.contains("connect(") {
        return None;
    }

    let address_regex = Regex::new(r#"inet_addr\("([^"]+)"\)"#).expect("valid inet regex");
    let port_regex = Regex::new(r#"sin_port=htons\((\d+)\)"#).expect("valid port regex");
    let address = address_regex.captures(line)?.get(1)?.as_str().to_string();
    let port = port_regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .and_then(|port| port.as_str().parse().ok());

    Some(TraceNetworkConnect { address, port })
}

fn syscall_name(line: &str) -> Option<String> {
    let open_paren = line.find('(')?;
    let before = &line[..open_paren];
    let name = before.split_whitespace().last()?;
    Some(name.to_string())
}

fn quoted_strings(line: &str) -> Vec<String> {
    let quoted_regex = Regex::new(r#""((?:\\.|[^"\\])*)""#).expect("valid quoted regex");

    quoted_regex
        .captures_iter(line)
        .filter_map(|captures| captures.get(1).map(|match_| unescape(match_.as_str())))
        .collect()
}

fn parse_exec_args(line: &str) -> Option<Vec<String>> {
    let args_start = line.find('[')?;
    let args_end = line[args_start..].find(']')? + args_start;
    let args_text = &line[args_start..=args_end];
    Some(quoted_strings(args_text))
}

fn parse_open_flags(line: &str) -> Option<String> {
    let flag_regex = Regex::new(r#",\s*(O_[A-Z0-9_|]+)"#).expect("valid flag regex");
    flag_regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|flags| flags.as_str().to_string())
}

fn parse_result(line: &str) -> Option<String> {
    line.rsplit_once(" = ")
        .map(|(_, result)| result.trim().to_string())
}

fn is_internal_path(path: &str) -> bool {
    path == "/glassbox-out" || path.starts_with("/glassbox-out/")
}

fn unescape(value: &str) -> String {
    value.replace("\\\"", "\"").replace("\\\\", "\\")
}

fn dedup<T>(values: Vec<T>) -> Vec<T>
where
    T: Clone + Ord,
{
    values
        .into_iter()
        .map(|value| (value.clone_key(), value))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

trait CloneKey: Clone {
    fn clone_key(&self) -> Self {
        self.clone()
    }
}

impl<T> CloneKey for T where T: Clone {}

#[cfg(test)]
mod tests {
    use super::{parse_execve, parse_file_access, parse_file_mutation, parse_network_connect};

    #[test]
    fn parses_execve() {
        let event = parse_execve(
            r#"12:00:00 execve("/usr/bin/curl", ["curl", "https://example.com"], 0x7ffd) = 0"#,
        )
        .unwrap();

        assert_eq!(event.path, "/usr/bin/curl");
        assert_eq!(event.args, vec!["curl", "https://example.com"]);
    }

    #[test]
    fn parses_openat_file_access() {
        let access =
            parse_file_access(r#"openat(AT_FDCWD, "/root/.bashrc", O_WRONLY|O_APPEND) = 3"#)
                .unwrap();

        assert_eq!(access.syscall, "openat");
        assert_eq!(access.path, "/root/.bashrc");
        assert_eq!(access.flags, Some("O_WRONLY|O_APPEND".to_string()));
    }

    #[test]
    fn parses_file_mutation() {
        let mutation = parse_file_mutation(r#"unlinkat(AT_FDCWD, "/tmp/example", 0) = 0"#).unwrap();

        assert_eq!(mutation.syscall, "unlinkat");
        assert_eq!(mutation.path, "/tmp/example");
        assert_eq!(mutation.detail, Some("0".to_string()));
    }

    #[test]
    fn parses_network_connect() {
        let connect = parse_network_connect(
            r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0"#,
        )
        .unwrap();

        assert_eq!(connect.address, "93.184.216.34");
        assert_eq!(connect.port, Some(443));
    }
}
