use crate::docker::DockerRunner;
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallerMetadata {
    pub source_url: String,
    pub resolved_url: String,
    pub sha256: String,
    pub size_bytes: usize,
    pub shell: String,
}

#[derive(Debug)]
pub struct FrozenInstaller {
    pub metadata: InstallerMetadata,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallerSpec {
    source_url: String,
    shell: String,
}

pub fn freeze_if_supported(
    command: &str,
    runner: &DockerRunner,
) -> Result<Option<FrozenInstaller>> {
    let Some(spec) = detect_installer(command) else {
        return Ok(None);
    };

    let fetched = runner.fetch_url(&spec.source_url)?;
    let sha256 = format!("{:x}", Sha256::digest(&fetched.bytes));

    Ok(Some(FrozenInstaller {
        metadata: InstallerMetadata {
            source_url: spec.source_url,
            resolved_url: fetched.resolved_url,
            sha256,
            size_bytes: fetched.bytes.len(),
            shell: spec.shell,
        },
        bytes: fetched.bytes,
    }))
}

fn detect_installer(command: &str) -> Option<InstallerSpec> {
    let mut pipeline = command.split('|');
    let downloader = pipeline.next()?.trim();
    let shell = pipeline.next()?.trim();

    if pipeline.next().is_some() {
        return None;
    }

    let downloader_name = downloader.split_whitespace().next()?;
    if !matches!(downloader_name, "curl" | "wget") {
        return None;
    }

    if !matches!(shell, "bash" | "sh") {
        return None;
    }

    let url_regex = Regex::new(r#"https?://[^\s'"<>|]+"#).expect("valid installer URL regex");
    let urls: Vec<&str> = url_regex
        .find_iter(downloader)
        .map(|match_| match_.as_str())
        .collect();

    if urls.len() != 1 {
        return None;
    }

    Some(InstallerSpec {
        source_url: urls[0].trim_end_matches(['.', ',', ';', ':']).to_string(),
        shell: shell.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::detect_installer;

    #[test]
    fn detects_simple_curl_pipe_bash() {
        let spec = detect_installer("curl -fsSL https://example.com/install.sh | bash").unwrap();

        assert_eq!(spec.source_url, "https://example.com/install.sh");
        assert_eq!(spec.shell, "bash");
    }

    #[test]
    fn detects_simple_wget_pipe_sh() {
        let spec = detect_installer("wget -qO- https://example.com/install.sh | sh").unwrap();

        assert_eq!(spec.source_url, "https://example.com/install.sh");
        assert_eq!(spec.shell, "sh");
    }

    #[test]
    fn ignores_complex_shell_pipelines() {
        assert!(
            detect_installer("curl -fsSL https://example.com/install.sh | sudo bash").is_none()
        );
        assert!(
            detect_installer("curl -fsSL https://example.com/install.sh | bash | tee result")
                .is_none()
        );
    }
}
