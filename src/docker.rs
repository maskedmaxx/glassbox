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
}

impl DockerRunner {
    pub fn new(image: String) -> Self {
        Self { image }
    }

    pub fn preview_command(&self, command: &str) -> String {
        format!(
            "docker run --rm --network bridge {} bash -lc {:?}",
            self.image, command
        )
    }

    pub fn run(&self, command: &str) -> Result<SandboxRun> {
        let started = Instant::now();
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "bridge",
                &self.image,
                "bash",
                "-lc",
                command,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "failed to start docker; is Docker installed and running?")?;

        Ok(SandboxRun {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: started.elapsed(),
        })
    }
}
