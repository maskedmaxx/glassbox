mod audit;
mod cli;
mod docker;
mod fsdiff;
mod report;
mod rules;
mod signals;

use anyhow::Result;
use cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Command::Audit(args) => audit::run(args),
    }
}
