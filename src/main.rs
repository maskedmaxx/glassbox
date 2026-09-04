mod audit;
mod cli;
mod contract;
mod docker;
mod fsdiff;
mod installer;
mod network;
mod policy;
mod process;
mod report;
mod rules;
mod signals;
mod trace;

use anyhow::Result;
use cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Command::Audit(args) => audit::run(args),
        Command::Lock(args) => {
            contract::create_lock(contract::LockOptions {
                name: args.name,
                command: args.command,
                image: args.image,
                out_dir: args.out,
            })?;
            Ok(())
        }
        Command::Diff(args) => {
            contract::diff_lock(contract::CheckOptions {
                lockfile: args.lockfile,
                command: args.command,
                image: args.image,
                policy: args.policy,
                strict_network: args.strict_network,
                verbose: args.verbose,
            })?;
            Ok(())
        }
        Command::Verify(args) => contract::verify_lock(contract::CheckOptions {
            lockfile: args.lockfile,
            command: args.command,
            image: args.image,
            policy: args.policy,
            strict_network: args.strict_network,
            verbose: args.verbose,
        }),
    }
}
