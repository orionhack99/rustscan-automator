# RustScan Automator

Reconnaissance automation that orchestrates [RustScan](https://github.com/RustScan/RustScan)
in place of nmap. It is modeled on the reconnaissance workflows of
[nmapAutomator](https://github.com/21y4d/nmapAutomator) but deliberately limits
itself to reconnaissance: exploitation and third-party enumeration tools
(nikto, dirb, gobuster, wfuzz, metasploit, and friends) are **out of scope** and
are blocked by a recon-only nmap allowlist.

## Scan modes

| `--type`          | What it does                                                                 |
| ----------------- | ---------------------------------------------------------------------------- |
| `port`            | Full-range TCP port discovery via RustScan greppable output.                 |
| `network`         | Live-host discovery over a bounded set of common ports (no ICMP ping mode).  |
| `service`         | Service/version recon using RustScan's nmap handoff (`-sV -sC`).             |
| `vuln`            | Recon-only vulnerability scripts via nmap's `vuln` category.                 |
| `udp`             | UDP port discovery (requires elevated privileges).                           |
| `full` / `all`    | Full-range sweep, then service and vulnerability reconnaissance.             |
| `recon`           | Built-in next-step guidance derived from a quick scan (no external tools).   |

## Usage

```sh
cargo build --release

# Full-range port discovery
./target/release/rustscan-automator -H 10.0.0.5 -t port

# Service/version recon on selected ports
./target/release/rustscan-automator -H scanme.example.com -t service --ports 22,80,443

# Comprehensive workflow into a custom output directory
./target/release/rustscan-automator -H 10.0.0.0/24 -t full -o ./results

# UDP discovery (needs sudo because RustScan requires raw sockets)
sudo ./target/release/rustscan-automator -H 10.0.0.5 -t udp --ports 53,123
```

Run `rustscan-automator --help` for the full option list.

## Output

Everything is written under `<output-dir>/<target-label>/`:

- `<target>_<mode>_<timestamp>.txt` and `.json` — per-mode findings.
- `<target>_summary_<timestamp>.txt` and `.json` — consolidated `RunSummary`.
- `<target>_session_<timestamp>.log` — a tee of the console session.

Existing files are never overwritten; colliding names get a `-1`, `-2`, ...
suffix.

## Exit codes

| Code | Meaning                |
| ---- | ---------------------- |
| 0    | Success                |
| 1    | Runtime failure        |
| 2    | Invalid input          |
| 3    | Missing dependency     |
| 4    | Privilege required     |

## Development

```sh
cargo test            # hermetic: never touches a live network
cargo clippy --all-targets
```

Tests inject a fake `CommandRunner`, so the suite replays canned RustScan output
instead of spawning real scans.

## Documentation

Full step-by-step usage instructions: [`docs/USAGE.md`](docs/USAGE.md).

## Ética e uso legal

Use somente em alvos para os quais você tem autorização explícita. Alvos
públicos de teste: `scanme.nmap.org`, `scanme.sh`.

