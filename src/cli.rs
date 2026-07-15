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

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
