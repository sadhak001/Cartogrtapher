"""
cartographer.cli - the command-line interface.

Structured as subcommands (cartographer dns example.com, cartographer
ports example.com, ...) rather than a pile of flags on one command,
the same pattern tools like git, docker, and aws use: one verb per
job, a shared set of global options, and --help that's actually
useful at every level.
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__
from .modules import dns_whois, subdomains, portscan, fingerprint


BANNER = r"""
   ___ __ _ _ __| |_ ___   __ _ _ __ __ _ _ __ | |__   ___ _ __
  / __/ _` | '__| __/ _ \ / _` | '__/ _` | '_ \| '_ \ / _ \ '__|
 | (_| (_| | |  | || (_) | (_| | | | (_| | |_) | | | |  __/ |
  \___\__,_|_|   \__\___/ \__, |_|  \__,_| .__/|_| |_|\___|_|
                           |___/         |_|
  map the surface before you explore it - authorized targets only
"""


class Color:
    CYAN = "\033[96m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"


_USE_COLOR = sys.stdout.isatty()


def c(text, color):
    return f"{color}{text}{Color.RESET}" if _USE_COLOR else text


def section(title):
    print(f"\n{c('[*] ' + title, Color.CYAN)}")


def error_line(msg):
    print(c(f"    error: {msg}", Color.RED))


def confirm_authorization(target):
    print(BANNER)
    print(f"Target: {target}\n")
    answer = input(
        "Type YES to confirm you own this target or have explicit "
        "written permission to test it: "
    )
    if answer.strip() != "YES":
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)


def run_dns_whois(domain, report):
    section("DNS records")
    dns_results = dns_whois.get_dns_records(domain)
    report["dns"] = dns_results
    for rtype, values in dns_results.items():
        print(f"    {rtype}: {values}")

    section("WHOIS")
    whois_results = dns_whois.get_whois_info(domain)
    report["whois"] = whois_results
    if "error" in whois_results:
        error_line(whois_results["error"])
    else:
        for key, value in whois_results.items():
            print(f"    {key}: {value}")


def run_subdomains(domain, report, wordlist_path=None):
    section("Subdomains - passive (crt.sh)")
    passive = subdomains.passive_subdomains_crtsh(domain)
    report["subdomains_passive"] = passive
    if passive["error"]:
        error_line(passive["error"])
    else:
        for sub in passive["results"][:50]:
            print(f"    {sub}")
        if len(passive["results"]) > 50:
            print(f"    ... and {len(passive['results']) - 50} more (see JSON output)")

    section("Subdomains - active brute force")
    wordlist = subdomains.load_wordlist_file(wordlist_path) if wordlist_path else None
    active = subdomains.active_subdomains_bruteforce(domain, wordlist=wordlist)
    report["subdomains_active"] = active
    for sub in active:
        print(f"    {sub}")


def run_portscan(target, report, ports=None):
    section("Port scan (this can take a minute)")
    results = portscan.scan_target(target, ports=ports or portscan.COMMON_PORTS)
    report["ports"] = results
    if "error" in results:
        error_line(results["error"])
        return
    for port, info in sorted(results.items()):
        print(f"    {port}/{info['protocol']:5s} {info['state']:8s} {info['service']} {info['product']} {info['version']}")


def run_fingerprint(domain, report):
    section("HTTP fingerprint")
    result = fingerprint.fingerprint_target(domain)
    report["fingerprint"] = result
    if "error" in result:
        error_line(result["error"])
        return
    for key, value in result.items():
        print(f"    {key}: {value}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cartographer",
        description="Map a target's exposed surface: DNS/WHOIS, subdomains, ports, and HTTP fingerprinting.",
    )
    parser.add_argument("--version", action="version", version=f"cartographer {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("target", help="Domain or IP to recon (e.g. example.com)")
    common.add_argument("--yes", action="store_true", help="Skip the interactive authorization prompt")
    common.add_argument("--output", help="Save results to a JSON file")

    subparsers.add_parser("dns", parents=[common], help="DNS records + WHOIS lookup")

    sub_p = subparsers.add_parser("subdomains", parents=[common], help="Subdomain enumeration (passive + active)")
    sub_p.add_argument("--wordlist", help="Path to a custom subdomain wordlist file")

    ports_p = subparsers.add_parser("ports", parents=[common], help="Port scan via nmap")
    ports_p.add_argument("--ports", default=portscan.COMMON_PORTS, help="Comma-separated ports to scan")

    subparsers.add_parser("http", parents=[common], help="HTTP header + tech fingerprint")

    all_p = subparsers.add_parser("all", parents=[common], help="Run every module")
    all_p.add_argument("--wordlist", help="Path to a custom subdomain wordlist file")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.yes:
        confirm_authorization(args.target)

    report = {
        "target": args.target,
        "command": args.command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if args.command in ("dns", "all"):
        run_dns_whois(args.target, report)
    if args.command in ("subdomains", "all"):
        run_subdomains(args.target, report, wordlist_path=getattr(args, "wordlist", None))
    if args.command in ("ports", "all"):
        run_portscan(args.target, report, ports=getattr(args, "ports", None))
    if args.command in ("http", "all"):
        run_fingerprint(args.target, report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n{c('[*] Full results saved to ' + args.output, Color.GREEN)}")


if __name__ == "__main__":
    main()
