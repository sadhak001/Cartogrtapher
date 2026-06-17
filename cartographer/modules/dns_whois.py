"""
DNS and WHOIS reconnaissance.

Passive recon: every answer here comes from third-party infrastructure
(public DNS resolvers, domain registries) that already publishes this
data. We never send a single packet to the target's own server.

DNS records map the target's infrastructure: which mail provider they
use (MX), which IPs serve the domain (A/AAAA), whether they outsource
DNS (NS), and what they've declared for things like SPF/DKIM (TXT) -
which itself can leak which third-party services they rely on.

WHOIS tells you who registered the domain and when, which matters for
things like domain-age checks (freshly registered domains are a
common phishing signal) and finding registrar-level contacts.
"""

import dns.resolver
import whois


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def get_dns_records(domain):
    """
    Query common DNS record types for a domain.
    Returns a dict of record_type -> list of values (or None if the
    domain itself doesn't exist).
    """
    results = {}

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [str(rdata).strip() for rdata in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            results[rtype] = None
            break
        except Exception as e:
            results[rtype] = [f"error: {e}"]

    return results


def get_whois_info(domain):
    """
    Query WHOIS registry data for a domain.
    Returns key registration details, or an error dict if the lookup fails
    (common for privacy-protected domains or rate-limited registries).
    """
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "org": w.org,
            "country": w.country,
        }
    except Exception as e:
        return {"error": str(e)}
