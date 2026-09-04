use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "glassbox")]
#[command(about = "Audit suspicious install commands in disposable sandboxes.")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a command in a sandbox and generate an audit report.
    Audit(AuditArgs),

    /// Run a command and save its observed behavior as a lockfile.
    Lock(LockArgs),

    /// Run a command and show how its behavior differs from a lockfile.
    Diff(CheckArgs),

    /// Run a command and fail if new behavior or risk escalation is observed.
    Verify(CheckArgs),
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Command to execute inside the sandbox.
    pub command: String,

    /// Docker image used for the audit environment.
    #[arg(long, default_value = "glassbox-audit:latest")]
    pub image: String,

    /// Directory where reports should be written.
    #[arg(long, default_value = ".")]
    pub out: PathBuf,

    /// Do not execute anything; print the planned sandbox command.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct LockArgs {
    /// Human-readable name for this behavioral contract.
    pub name: String,

    /// Command to execute inside the sandbox.
    pub command: String,

    /// Docker image used for the audit environment.
    #[arg(long, default_value = "glassbox-audit:latest")]
    pub image: String,

    /// Directory where the lockfile should be written.
    #[arg(long, default_value = ".")]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Path to a .glassbox.lock.json file.
    pub lockfile: PathBuf,

    /// Override the command stored in the lockfile.
    #[arg(long)]
    pub command: Option<String>,

    /// Override the Docker image stored in the lockfile.
    #[arg(long)]
    pub image: Option<String>,

    /// Optional YAML policy to enforce against observed behavior.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Treat changed network peer IP:port observations as blocking drift.
    ///
    /// By default, domain changes are blocking but raw peer-address changes
    /// are informational because CDNs and load balancers can make them noisy.
    #[arg(long)]
    pub strict_network: bool,

    /// Show individual informational process/network observations.
    #[arg(long)]
    pub verbose: bool,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
