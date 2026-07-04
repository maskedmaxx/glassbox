use crate::cli::AuditArgs;
use crate::docker::{DockerRunner, SandboxRun};
use crate::report::{AuditReport, ReportWriter};
use crate::rules::RuleEngine;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::fs;

pub fn run(args: AuditArgs) -> Result<()> {
    fs::create_dir_all(&args.out).with_context(|| {
        format!(
            "failed to create report output directory {}",
            args.out.display()
        )
    })?;

    let runner = DockerRunner::new(args.image.clone());

    if args.dry_run {
        println!("{}", "Glassbox dry run".bold());
        println!("Image: {}", args.image);
        println!("Command: {}", args.command);
        println!("Docker invocation:");
        println!("{}", runner.preview_command(&args.command));
        return Ok(());
    }

    println!("{}", "Glassbox audit starting".bold());
    println!("Command: {}", args.command);
    println!("Image: {}", args.image);

    let sandbox_run: SandboxRun = runner
        .run(&args.command)
        .context("sandbox execution failed")?;

    let findings = RuleEngine::default().evaluate(&sandbox_run);
    let report = AuditReport::from_run(args.command, args.image, sandbox_run, findings);
    let written = ReportWriter::new(args.out).write_all(&report)?;

    println!();
    println!("{}", "Audit complete".green().bold());
    println!("Markdown report: {}", written.markdown.display());
    println!("JSON report: {}", written.json.display());
    println!("Risk: {}", report.risk_label());

    Ok(())
}
