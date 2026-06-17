# cartographer

A small modular recon CLI, built for learning. Maps a target's exposed
surface across four techniques: DNS/WHOIS lookups, subdomain
enumeration (passive + active), port scanning via nmap, and HTTP
header/tech fingerprinting.

## Before you run this

Only point this at:
- infrastructure you own, or
- a target where you have explicit written authorization to test it
  (an in-scope bug bounty program, a signed pentest contract, or a
  deliberately vulnerable lab like a HackTheBox/TryHackMe machine)

The tool asks you to confirm authorization before it runs anything,
every time, unless you pass `--yes`.

## Install

```bash
pip install -e .
# nmap itself must also be installed on your system (python-nmap is
# just a wrapper around the real binary):
#   macOS:         brew install nmap
#   Debian/Ubuntu: sudo apt install nmap
#   Windows:       https://nmap.org/download.html
```

This installs a `cartographer` command on your PATH. No install? Run
it straight from the project folder instead:

```bash
pip install -r requirements.txt
python -m cartographer dns example.com
```

## Usage

Each recon technique is its own subcommand:

```bash
cartographer dns example.com
cartographer subdomains example.com --wordlist wordlists/big_list.txt
cartographer ports example.com --ports 80,443,8080
cartographer http example.com
cartographer all example.com --output results.json
cartographer --version
cartographer --help
cartographer subdomains --help
```

## What each module does

- **modules/dns_whois.py** - DNS record lookups (A, MX, NS, TXT...)
  and WHOIS registration data. Fully passive - you never touch the
  target, just public registries.
- **modules/subdomains.py** - passive enumeration via crt.sh
  certificate transparency logs, plus active brute-force DNS
  resolution against a wordlist.
- **modules/portscan.py** - wraps the real nmap binary via
  python-nmap to find open ports and detect running services/versions.
- **modules/fingerprint.py** - HTTP GET to inspect response headers,
  flag missing security headers, and pattern-match the page body for
  common framework signatures.

## A note on the sandbox this was built in

Modules were built and tested in a sandboxed environment with outbound
network access restricted to package registries only, so live lookups
against real domains (DNS, crt.sh, arbitrary HTTP targets) couldn't be
demonstrated end-to-end there. Port scanning and HTTP fingerprinting
were verified against localhost. Install it locally and run it against
a target you're authorized to test for the full picture.
