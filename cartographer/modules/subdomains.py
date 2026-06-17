"""
Subdomain enumeration - two techniques, two different risk profiles.

1. Passive (crt.sh): every public TLS certificate ever issued gets
   logged permanently in Certificate Transparency logs - a system
   created specifically so misissued certs can be caught. Searching
   that log reveals subdomains the organization has issued certs for,
   without sending the target a single packet. This is the safest,
   quietest recon technique that exists.

2. Active (brute force): we guess common subdomain names (www, dev,
   staging, api...) and ask DNS "does this resolve?" Each guess is a
   real DNS query that the target's DNS provider could see and log.
   Still far short of touching their actual server, but a meaningful
   step up from crt.sh in footprint.

Real engagements usually run passive first, then active only against
in-scope targets - the order this module is written in.
"""

from pathlib import Path
import requests
import dns.resolver
import concurrent.futures


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "staging", "test", "api", "admin",
    "portal", "vpn", "remote", "webmail", "ns1", "ns2", "smtp", "blog",
    "shop", "m", "mobile", "app", "cdn", "static", "support", "docs",
    "git", "jenkins", "demo", "beta", "internal", "dashboard",
]

# Resolves to <package_root>/wordlists/subdomains_small.txt regardless of
# the directory the CLI is actually run from - important once this is
# pip-installed and invoked from anywhere on the system.
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORDLIST_PATH = PACKAGE_ROOT / "wordlists" / "subdomains_small.txt"


def load_wordlist_file(path):
    """Load one subdomain prefix per line from a text file, skipping blanks/comments."""
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _default_wordlist():
    try:
        return load_wordlist_file(DEFAULT_WORDLIST_PATH)
    except Exception:
        return COMMON_SUBDOMAINS


def passive_subdomains_crtsh(domain):
    """
    Query crt.sh for every certificate ever issued for *.domain.
    Returns a sorted list of unique subdomains found in those certs.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    found = set()

    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lstrip("*.")
                if line.endswith(domain):
                    found.add(line)
    except Exception as e:
        return {"error": str(e), "results": []}

    return {"error": None, "results": sorted(found)}


def _try_resolve(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        dns.resolver.resolve(fqdn, "A", lifetime=3)
        return fqdn
    except Exception:
        return None


def active_subdomains_bruteforce(domain, wordlist=None, max_workers=20):
    """
    Try candidate subdomain prefixes and see which ones actually resolve.
    Defaults to the bundled wordlist file, falling back to a small
    in-code list if that file is missing for some reason.

    Runs lookups concurrently with threads - each lookup just waits on
    a network reply, so this is I/O-bound and threading helps a lot
    here even with Python's GIL.
    """
    wordlist = wordlist or _default_wordlist()
    found = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_try_resolve, sub, domain) for sub in wordlist]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found)
