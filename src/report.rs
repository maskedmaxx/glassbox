use crate::docker::SandboxRun;
use crate::fsdiff::FilesystemDiff;
use crate::rules::{Finding, Severity};
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub command: String,
    pub image: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub stdout_preview: String,
    pub stderr_preview: String,
    pub filesystem_diff: FilesystemDiff,
    pub findings: Vec<Finding>,
}

#[derive(Debug)]
pub struct WrittenReports {
    pub markdown: PathBuf,
    pub json: PathBuf,
}

pub struct ReportWriter {
    out_dir: PathBuf,
}

impl AuditReport {
    pub fn from_run(
        command: String,
        image: String,
        run: SandboxRun,
        findings: Vec<Finding>,
    ) -> Self {
        Self {
            command,
            image,
            exit_code: run.exit_code,
            duration_ms: run.duration.as_millis(),
            stdout_preview: preview(&run.stdout),
            stderr_preview: preview(&run.stderr),
            filesystem_diff: run.filesystem_diff,
            findings,
        }
    }

    pub fn risk_label(&self) -> &'static str {
        if self
            .findings
            .iter()
            .any(|finding| finding.severity == Severity::High)
        {
            "high"
        } else if self
            .findings
            .iter()
            .any(|finding| finding.severity == Severity::Medium)
        {
            "medium"
        } else {
            "low"
        }
    }

    fn to_markdown(&self) -> String {
        let mut body = String::new();
        body.push_str("# Glassbox Audit Report\n\n");
        body.push_str(&format!("**Command:** `{}`\n\n", self.command));
        body.push_str(&format!("**Image:** `{}`\n\n", self.image));
        body.push_str(&format!("**Exit code:** `{:?}`\n\n", self.exit_code));
        body.push_str(&format!("**Duration:** `{} ms`\n\n", self.duration_ms));
        body.push_str(&format!("**Risk:** `{}`\n\n", self.risk_label()));
        body.push_str(&format!(
            "**Filesystem changes:** `{}`\n\n",
            self.filesystem_diff.changed_file_count()
        ));

        body.push_str("## Findings\n\n");
        if self.findings.is_empty() {
            body.push_str("No notable risk signals detected by the current rules.\n\n");
        } else {
            for finding in &self.findings {
                body.push_str(&format!(
                    "- **{:?}:** {} - {}\n",
                    finding.severity, finding.title, finding.detail
                ));
            }
            body.push('\n');
        }

        body.push_str("## Filesystem Changes\n\n");
        write_file_list(&mut body, "Created", &self.filesystem_diff.created);
        write_modified_file_list(&mut body, "Modified", &self.filesystem_diff.modified);
        write_file_list(&mut body, "Deleted", &self.filesystem_diff.deleted);

        body.push_str("## Output Preview\n\n");
        body.push_str("### stdout\n\n```text\n");
        body.push_str(&self.stdout_preview);
        body.push_str("\n```\n\n");
        body.push_str("### stderr\n\n```text\n");
        body.push_str(&self.stderr_preview);
        body.push_str("\n```\n");

        body
    }
}

fn write_file_list(body: &mut String, title: &str, files: &[crate::fsdiff::FileEntry]) {
    const MAX_FILES: usize = 40;

    body.push_str(&format!("### {}\n\n", title));

    if files.is_empty() {
        body.push_str("None detected.\n\n");
        return;
    }

    for file in files.iter().take(MAX_FILES) {
        body.push_str(&format!("- `{}` ({} bytes, {})\n", file.path, file.size, file.kind));
    }

    if files.len() > MAX_FILES {
        body.push_str(&format!("- ...{} more\n", files.len() - MAX_FILES));
    }

    body.push('\n');
}

fn write_modified_file_list(
    body: &mut String,
    title: &str,
    files: &[crate::fsdiff::ModifiedFile],
) {
    const MAX_FILES: usize = 40;

    body.push_str(&format!("### {}\n\n", title));

    if files.is_empty() {
        body.push_str("None detected.\n\n");
        return;
    }

    for file in files.iter().take(MAX_FILES) {
        body.push_str(&format!(
            "- `{}` ({} -> {} bytes, mode {} -> {})\n",
            file.path, file.before_size, file.after_size, file.before_mode, file.after_mode
        ));
    }

    if files.len() > MAX_FILES {
        body.push_str(&format!("- ...{} more\n", files.len() - MAX_FILES));
    }

    body.push('\n');
}

impl ReportWriter {
    pub fn new(out_dir: PathBuf) -> Self {
        Self { out_dir }
    }

    pub fn write_all(&self, report: &AuditReport) -> Result<WrittenReports> {
        let markdown = self.out_dir.join("glassbox-report.md");
        let json = self.out_dir.join("glassbox-report.json");

        fs::write(&markdown, report.to_markdown())
            .with_context(|| format!("failed to write {}", markdown.display()))?;
        fs::write(&json, serde_json::to_string_pretty(report)?)
            .with_context(|| format!("failed to write {}", json.display()))?;

        Ok(WrittenReports { markdown, json })
    }
}

fn preview(value: &str) -> String {
    const MAX_CHARS: usize = 4_000;

    if value.chars().count() <= MAX_CHARS {
        return value.trim().to_string();
    }

    let clipped: String = value.chars().take(MAX_CHARS).collect();
    format!("{}\n...[output clipped]", clipped.trim())
}
