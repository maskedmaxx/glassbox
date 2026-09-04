use crate::fsdiff::FilesystemDiff;
use crate::network::NetworkSummary;
use crate::process::ProcessSummary;
use crate::trace::TraceSummary;
use anyhow::{bail, Context, Result};
use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DockerRunner {
    image: String,
}

#[derive(Debug, Clone)]
pub struct SandboxRun {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub filesystem_diff: FilesystemDiff,
    pub process_summary: ProcessSummary,
    pub network_summary: NetworkSummary,
    pub trace_summary: TraceSummary,
}

#[derive(Debug, Clone)]
pub struct FetchedUrl {
    pub bytes: Vec<u8>,
    pub resolved_url: String,
}

impl DockerRunner {
    pub fn new(image: String) -> Self {
        Self { image }
    }

    pub fn preview_command(&self, command: &str) -> String {
        format!(
            "docker run --rm --network bridge -e GLASSBOX_COMMAND={:?} {} bash -lc <glassbox audit script>",
            command, self.image
        )
    }

    pub fn fetch_url(&self, url: &str) -> Result<FetchedUrl> {
        let fetch_dir =
            tempfile::tempdir().context("failed to create temporary installer fetch directory")?;
        let payload_path = fetch_dir.path().join("payload");
        let volume = format!("{}:/glassbox-out", fetch_dir.path().display());
        let url_env = format!("GLASSBOX_URL={url}");

        let fetch_script = r#"
set -e
curl \
  --fail \
  --silent \
  --show-error \
  --location \
  --retry 2 \
  --connect-timeout 10 \
  --output /glassbox-out/payload \
  --write-out '%{url_effective}' \
  "$GLASSBOX_URL"
"#;

        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "bridge",
                "-v",
                volume.as_str(),
                "-e",
                url_env.as_str(),
                self.image.as_str(),
                "bash",
                "-lc",
                fetch_script,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "failed to start docker while freezing installer")?;

        if !output.status.success() {
            bail!(
                "failed to freeze installer from {url}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let bytes = fs::read(&payload_path).with_context(|| {
            format!("failed to read frozen installer {}", payload_path.display())
        })?;

        if bytes.is_empty() {
            bail!("installer fetch from {url} returned an empty payload");
        }

        let resolved_url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let resolved_url = if resolved_url.is_empty() {
            url.to_string()
        } else {
            resolved_url
        };

        Ok(FetchedUrl {
            bytes,
            resolved_url,
        })
    }

    pub fn run(&self, command: &str) -> Result<SandboxRun> {
        self.run_internal(command, None)
    }

    pub fn run_script_bytes(&self, bytes: &[u8], shell: &str) -> Result<SandboxRun> {
        let command = format!("{shell} /glassbox-out/frozen-installer");
        self.run_internal(&command, Some(bytes))
    }

    fn run_internal(&self, command: &str, frozen_script: Option<&[u8]>) -> Result<SandboxRun> {
        let started = Instant::now();
        let audit_dir =
            tempfile::tempdir().context("failed to create temporary audit directory")?;

        if let Some(bytes) = frozen_script {
            let frozen_path = audit_dir.path().join("frozen-installer");
            fs::write(&frozen_path, bytes).with_context(|| {
                format!(
                    "failed to stage frozen installer at {}",
                    frozen_path.display()
                )
            })?;
        }

        let before_manifest = audit_dir.path().join("before.tsv");
        let after_manifest = audit_dir.path().join("after.tsv");
        let process_log = audit_dir.path().join("processes.log");
        let network_log = audit_dir.path().join("network.log");
        let volume = format!("{}:/glassbox-out", audit_dir.path().display());
        let command_env = format!("GLASSBOX_COMMAND={command}");
        let audit_script = r#"
set +e

capture_processes() {
  ps -eo pid=,ppid=,comm=,args= --no-headers 2>/dev/null >> /glassbox-out/processes.log || true
}

capture_network() {
  ss -tunpH 2>/dev/null >> /glassbox-out/network.log || true
}

find / -xdev -printf '%p\t%s\t%T@\t%m\t%y\n' 2>/dev/null | sort > /glassbox-out/before.tsv
capture_processes
capture_network

strace -ff -s 256 -o /glassbox-out/strace bash -lc "$GLASSBOX_COMMAND" &
glassbox_pid=$!

while kill -0 "$glassbox_pid" 2>/dev/null; do
  capture_processes
  capture_network
  sleep 0.2
done

wait "$glassbox_pid"
glassbox_status=$?

capture_processes
capture_network
find / -xdev -printf '%p\t%s\t%T@\t%m\t%y\n' 2>/dev/null | sort > /glassbox-out/after.tsv
exit "$glassbox_status"
"#;

        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "bridge",
                "-v",
                volume.as_str(),
                "-e",
                command_env.as_str(),
                self.image.as_str(),
                "bash",
                "-lc",
                audit_script,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "failed to start docker; is Docker installed and running?")?;

        let filesystem_diff =
            FilesystemDiff::from_manifest_files(&before_manifest, &after_manifest)
                .context("failed to build filesystem diff from sandbox manifests")?;
        let process_summary = ProcessSummary::from_log_file(&process_log)
            .context("failed to build process summary from sandbox log")?;
        let network_summary = NetworkSummary::from_log_file(&network_log)
            .context("failed to build network summary from sandbox log")?;
        let trace_summary = TraceSummary::from_log_dir(audit_dir.path(), "strace")
            .context("failed to build strace summary from sandbox trace logs")?;

        Ok(SandboxRun {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: started.elapsed(),
            filesystem_diff,
            process_summary,
            network_summary,
            trace_summary,
        })
    }
}
