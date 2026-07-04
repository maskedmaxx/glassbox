use crate::fsdiff::FilesystemDiff;
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
        let audit_dir = tempfile::tempdir().context("failed to create temporary audit directory")?;
        let before_manifest = audit_dir.path().join("before.tsv");
        let after_manifest = audit_dir.path().join("after.tsv");
        let volume = format!("{}:/glassbox-out", audit_dir.path().display());
        let command_env = format!("GLASSBOX_COMMAND={command}");
        let audit_script = r#"
set +e
find / -xdev -printf '%p\t%s\t%T@\t%m\t%y\n' 2>/dev/null | sort > /glassbox-out/before.tsv
bash -lc "$GLASSBOX_COMMAND"
glassbox_status=$?
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
                &volume,
                "-e",
                &command_env,
                &self.image,
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

        Ok(SandboxRun {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: started.elapsed(),
            filesystem_diff,
        })
    }
}
