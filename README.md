# Glassbox

Glassbox shows what install scripts do before you trust them.

```bash
glassbox audit "curl -fsSL https://example.com/install.sh | bash"
```

Instead of running an unfamiliar installer directly on your machine, Glassbox runs it inside a disposable Docker sandbox and records what it actually does.

It can show you:

- files created, changed, or deleted
- programs and processes executed
- network connections and domains contacted
- files read from sensitive locations
- shell profiles modified
- syscall activity captured with `strace`
- suspicious behavior such as `sudo`, SSH access, token access, or binary downloads

Glassbox then produces a human-readable Markdown report and a machine-readable JSON report.

## Why this exists

Developers routinely run commands like:

```bash
curl -fsSL https://example.com/install.sh | bash
```

That usually means trusting code you have not reviewed.

Glassbox gives you another option:

```text
install command
      ↓
run inside sandbox
      ↓
observe behavior
      ↓
review what happened
      ↓
decide whether you trust it
```

Glassbox is an audit tool, not a malware detector.

It does not try to prove that a script is safe. Its goal is to make installer behavior visible enough for a human or CI system to review.

## Quick start

Build the audit image:

```bash
docker build -t glassbox-audit:latest -f docker/audit-image.Dockerfile .
```

On Windows PowerShell:

```powershell
./scripts/build-audit-image.ps1
```

Run a simple audit:

```bash
cargo run -- audit "touch /hello-from-glassbox"
```

Or inspect a command that changes a shell profile:

```bash
cargo run -- audit "echo 'export PATH=/demo:$PATH' >> ~/.bashrc"
```

By default, Glassbox uses the Docker image:

```text
glassbox-audit:latest
```

Audit reports are written to:

```text
glassbox-report.md
glassbox-report.json
```

If the image build fails with a Docker pipe error, start Docker Desktop and make sure the Linux engine is running.

## Behavioral lockfiles

Glassbox can record the expected behavior of an installer and compare future runs against it.

Create a behavioral lockfile:

```bash
cargo run -- lock rustup "curl -fsSL https://sh.rustup.rs | sh"
```

Glassbox freezes the installer, runs it in the sandbox, observes its behavior, and records a behavioral contract.

The lockfile includes information such as:

- installer SHA-256
- domains contacted
- programs executed
- relevant file reads
- files created, modified, or deleted
- sensitive paths touched
- observed network peers
- overall risk level

The result is written to:

```text
rustup.glassbox.lock.json
```

You can think of it as a lockfile for installer side effects.

```text
freeze → hash → observe → lock → diff → verify
```

## Compare behavior

Run the installer again and compare its current behavior against the lockfile:

```bash
cargo run -- diff rustup.glassbox.lock.json
```

Glassbox reports behavior that appeared, disappeared, or changed.

For example:

```text
Behavioral observations changed

Blocking drift
  none

Informational changes
  process samples: +2 / -1
  network peers:   +1 / -1
  use --verbose to show individual informational observations
```

Use `--verbose` to inspect every observation:

```bash
cargo run -- diff rustup.glassbox.lock.json --verbose
```

## Verify behavior

Use `verify` when you want Glassbox to enforce the behavioral contract:

```bash
cargo run -- verify rustup.glassbox.lock.json
```

Verification can fail when the installer gains new capabilities or its risk level increases.

Examples of behavior that may be considered blocking:

- contacting a new domain
- executing a new program
- reading a new sensitive path
- writing to a new location
- modifying a shell profile
- touching sensitive files
- increasing the overall risk level

Transient runtime observations are treated differently.

Process sampling can vary between runs, and CDN-backed domains may resolve to different IP addresses. Glassbox treats those observations as informational by default.

Example:

```text
Behavioral observations changed

Blocking drift
  none

Informational changes
  process samples: +3 / -1
  network peers:   +1 / -1

Verification passed: only non-blocking behavior changed.
```

Raw network peer changes can be made strict with:

```bash
cargo run -- verify rustup.glassbox.lock.json --strict-network
```

## Installer freezing

For supported installer commands such as:

```bash
curl -fsSL https://sh.rustup.rs | sh
```

Glassbox does not immediately execute the remote response.

Instead, it:

1. detects the installer pipeline
2. fetches the installer inside Docker
3. follows redirects
4. captures the exact installer bytes
5. calculates a SHA-256 hash
6. executes those exact bytes inside the audit sandbox

Example:

```text
Installer freezing enabled

Frozen installer:
  source:   https://sh.rustup.rs
  resolved: https://sh.rustup.rs/
  sha256:   7d0ea0f8eba7fa1ebfe998091cd7ec4501e33ec5ca6b884eb4d894d7da5170af
  size:     29915 bytes

Executing the exact captured bytes inside the audit sandbox.
```

This makes an audit more reproducible because Glassbox records which installer payload was actually executed.

Installer freezing currently targets simple pipelines such as:

```bash
curl https://example.com/install.sh | sh
curl https://example.com/install.sh | bash
wget -qO- https://example.com/install.sh | sh
```

More complex shell pipelines may fall back to normal sandbox execution.

## Policy enforcement

Glassbox can enforce behavior rules using a YAML policy.

Example:

```yaml
max_risk: medium

allow:
  domains: []
  reads: []
  writes: []
  exec: []

deny:
  domains: []
  reads:
    - "$HOME/.ssh/**"
    - "$HOME/.aws/**"
    - "$HOME/.npmrc"
    - "$HOME/.netrc"
    - "$HOME/.pypirc"
  writes:
    - "$HOME/.ssh/**"
  exec: []
  privilege_escalation: true
```

Verify a behavioral lockfile against a policy:

```bash
cargo run -- verify rustup.glassbox.lock.json \
  --policy glassbox-policy.example.yaml
```

Policies can restrict:

- domains
- file reads
- file writes
- executed programs
- privilege escalation
- maximum allowed risk

Empty allow lists mean the category is unrestricted.

Once an allow list contains entries, observed behavior in that category must match at least one allowed pattern.

## What Glassbox captures

Glassbox combines several sources of runtime evidence.

### Filesystem changes

Glassbox snapshots the sandbox filesystem before and after execution and reports:

- created files
- modified files
- deleted files

### File reads

Relevant file accesses observed through tracing can be recorded in behavioral lockfiles.

Container-specific paths are normalized where possible.

For example:

```text
/root/.bashrc
```

becomes:

```text
$HOME/.bashrc
```

and:

```text
/workspace/project
```

becomes:

```text
$WORKSPACE/project
```

Temporary paths are normalized to reduce meaningless drift.

### Executed programs

Glassbox uses `strace` execution events as the stable source for executable capabilities.

For example:

```text
execve("/usr/bin/curl", ...)
execve("/usr/bin/bash", ...)
```

These are suitable for behavioral verification.

### Process sampling

Glassbox also samples running processes during an audit.

Short-lived commands may appear in one run and disappear in another, so process samples are treated as informational telemetry rather than blocking contract behavior.

### Network activity

Glassbox records:

- observed sockets
- destination peers
- URLs
- domains

Raw destination IP addresses may change because of CDNs, load balancing, or DNS behavior.

For that reason, network peer drift is informational by default.

### Syscall tracing

Glassbox uses `strace` to observe runtime activity such as:

- executed programs
- file access
- network-related syscalls
- sensitive filesystem behavior

### Behavioral signals

Glassbox extracts higher-level signals from the observed runtime behavior, including:

- URLs
- domains
- command tokens
- sensitive paths
- shell profile changes

### Risk findings

Starter rules flag behavior such as:

- `sudo`
- shell profile modification
- SSH-related access
- sensitive credential paths
- downloads
- destructive commands
- permission changes
- suspicious executable behavior
- network connections

The resulting findings contribute to a risk level such as:

```text
low
medium
high
```

## Reports

A normal audit produces:

```text
glassbox-report.md
glassbox-report.json
```

The Markdown report is intended for human review.

The JSON report is intended for automation, tooling, and future integrations.

Behavioral contracts are stored separately as:

```text
<name>.glassbox.lock.json
```

For example:

```text
rustup.glassbox.lock.json
```

## Example workflow

Audit an installer:

```bash
cargo run -- audit "curl -fsSL https://sh.rustup.rs | sh"
```

Create a behavioral lock:

```bash
cargo run -- lock rustup "curl -fsSL https://sh.rustup.rs | sh"
```

Compare a later run:

```bash
cargo run -- diff rustup.glassbox.lock.json
```

Verify that no blocking behavior was added:

```bash
cargo run -- verify rustup.glassbox.lock.json
```

Verify it against an explicit security policy:

```bash
cargo run -- verify rustup.glassbox.lock.json \
  --policy glassbox-policy.example.yaml
```

Inspect noisy runtime details when needed:

```bash
cargo run -- diff rustup.glassbox.lock.json --verbose
```

## Limitations

- Commands may behave differently inside a sandbox than on a real machine.
- Some installers detect containers and change their behavior.
- GUI, hardware, credential-manager, SSH-agent, and host-specific workflows are not first-class targets.
- Raw network IP addresses may change between runs because of CDNs, DNS, and load balancing.
- Process sampling can miss short-lived processes.
- Bash-in-Docker is currently the primary execution environment.
- Installer freezing currently supports a limited set of simple shell pipelines.
- Glassbox should not be treated as proof that a script is safe.

## Safety model

Glassbox reduces the amount of trust required to inspect an installer, but sandboxing is not a perfect security boundary.

A clean Glassbox report does not guarantee that software is safe, and malicious software may attempt to behave differently when it detects a sandbox.

Treat Glassbox output as evidence for review, not as a guarantee.

The goal is simple:

> Make installer behavior visible before you decide to trust it.

