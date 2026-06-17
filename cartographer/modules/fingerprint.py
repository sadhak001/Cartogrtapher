"""
HTTP header inspection and lightweight tech-stack fingerprinting.

Two layers of signal here:

1. Headers - a server tells you things directly (Server, X-Powered-By
   often reveal exact software/versions) and indirectly through what
   it omits. Missing security headers (no Content-Security-Policy, no
   Strict-Transport-Security...) is itself a finding - it maps
   straight onto OWASP A05, Security Misconfiguration.

2. Body patterns - frameworks leave fingerprints in HTML/JS even when
   headers are deliberately scrubbed. A WordPress site will reference
   /wp-content/ somewhere on almost every page, regardless of what
   the Server header claims. This is a tiny hand-rolled version of
   what tools like Wappalyzer do at scale.
"""

import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "Django": ["csrfmiddlewaretoken"],
    "Next.js": ["_next/static"],
    "React": ["data-reactroot", "react-dom"],
    "Laravel": ["laravel_session"],
    "Drupal": ["Drupal.settings"],
    "Shopify": ["cdn.shopify.com"],
}


def fingerprint_target(target, timeout=10):
    """
    Retrieve headers and identify simple technology fingerprints.

    Accepts either:
        example.com
        https://example.com
        http://example.com
    """

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": (
                "Cartographer/0.1 "
                "(Educational Recon Tool)"
            )
        }
    )

    urls_to_try = []

    if target.startswith(("http://", "https://")):
        urls_to_try.append(target)
    else:
        urls_to_try.extend([
            f"https://{target}",
            f"http://{target}",
        ])

    last_error = None

    for url in urls_to_try:

        try:
            resp = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
            )

            headers = dict(resp.headers)

            missing_security_headers = [
                h for h in SECURITY_HEADERS
                if h not in headers
            ]

            body = resp.text

            detected_tech = [
                name
                for name, signatures in TECH_SIGNATURES.items()
                if any(sig in body for sig in signatures)
            ]

            return {
                "final_url": resp.url,
                "status_code": resp.status_code,
                "server_header": headers.get(
                    "Server",
                    "not disclosed",
                ),
                "powered_by": headers.get(
                    "X-Powered-By",
                    "not disclosed",
                ),
                "missing_security_headers":
                    missing_security_headers,
                "detected_technologies":
                    detected_tech
                    or ["none matched"],
                "content_type":
                    headers.get("Content-Type"),
                "content_length":
                    headers.get("Content-Length"),
            }

        except requests.RequestException as e:
            last_error = str(e)

    return {"error": last_error}