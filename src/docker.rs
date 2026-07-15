use crate::fsdiff::FilesystemDiff;
use crate::network::NetworkSummary;
use crate::process::ProcessSummary;
use anyhow::{Context, Result};
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

    pub fn run(&self, command: &str) -> Result<SandboxRun> {
        let started = Instant::now();
        let audit_dir =
            tempfile::tempdir().context("failed to create temporary audit directory")?;
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

bash -lc "$GLASSBOX_COMMAND" &
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

        Ok(SandboxRun {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: started.elapsed(),
            filesystem_diff,
            process_summary,
            network_summary,
        })
    }
}
