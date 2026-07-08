use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub command: String,
    pub args: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessSummary {
    pub observed: Vec<ProcessEvent>,
}

impl ProcessSummary {
    pub fn from_log_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read process log {}", path.display()))?;
        let mut observed = BTreeMap::new();

        for line in contents.lines() {
            if let Some(event) = parse_process_line(line) {
                observed.insert(
                    (
                        event.command.clone(),
                        event.args.clone(),
                        event.pid,
                        event.ppid,
                    ),
                    event,
                );
            }
        }

        Ok(Self {
            observed: observed.into_values().collect(),
        })
    }

    pub fn count(&self) -> usize {
        self.observed.len()
    }

    pub fn commands(&self) -> Vec<String> {
        self.observed
            .iter()
            .map(|event| event.command.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn saw_command(&self, command: &str) -> bool {
        self.observed.iter().any(|event| event.command == command)
    }
}

fn parse_process_line(line: &str) -> Option<ProcessEvent> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 3 {
        return None;
    }

    let pid = parts[0].parse().ok()?;
    let ppid = parts[1].parse().ok()?;
    let command = parts[2].to_string();
    let args = if parts.len() > 3 {
        parts[3..].join(" ")
    } else {
        String::new()
    };

    Some(ProcessEvent {
        pid,
        ppid,
        command,
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_process_line;

    #[test]
    fn parses_process_line_with_args() {
        let event = parse_process_line("12 1 bash bash -lc curl https://example.com").unwrap();

        assert_eq!(event.pid, 12);
        assert_eq!(event.ppid, 1);
        assert_eq!(event.command, "bash");
        assert_eq!(event.args, "bash -lc curl https://example.com");
    }
}
