# Cartographer

A modular reconnaissance CLI built for learning and authorized security assessment. Cartographer maps a target's exposed attack surface through DNS and WHOIS lookups, subdomain enumeration, port scanning, and HTTP fingerprinting.

> **Educational Use Only**
>
> This tool must only be used against systems you own or are explicitly authorized to test. Unauthorized scanning or reconnaissance may violate laws, regulations, or service agreements.

---

## Features

* DNS resolution and basic WHOIS lookups
* Passive and active subdomain enumeration
* Port discovery using Nmap
* HTTP header collection
* Basic technology fingerprinting
* Modular architecture for adding new reconnaissance modules
* JSON output for automation and reporting

---

## Project Structure

```text
cartographer/
├── cartographer/
│   ├── dns.py
│   ├── subdomains.py
│   ├── ports.py
│   ├── fingerprint.py
│   └── utils.py
├── output/
├── examples/
├── tests/
├── requirements.txt
├── README.md
└── main.py
```

---

## Requirements

* Python 3.10+
* Nmap installed and accessible from PATH

Verify Nmap installation:

```bash
nmap --version
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/cartographer.git
cd cartographer
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

Linux/macOS:

```bash
source venv/bin/activate
```

Windows:

```powershell
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Basic scan:

```bash
python main.py example.com
```

Example output:

```text
[+] Resolving DNS records...
[+] Enumerating subdomains...
[+] Running port scan...
[+] Collecting HTTP headers...
[+] Fingerprinting technologies...

Target: example.com

Open Ports:
- 80/tcp
- 443/tcp

Detected Technologies:
- nginx
- PHP

Discovered Subdomains:
- api.example.com
- dev.example.com
```

---

## Modules

### DNS & WHOIS

Collects basic DNS information and domain registration metadata.

### Subdomain Enumeration

Uses passive and active techniques to discover publicly reachable subdomains.

### Port Scanning

Performs service discovery using Nmap.

### HTTP Fingerprinting

Collects HTTP response headers and identifies common technologies.

---

## Example Workflow

```text
Target Domain
      │
      ▼
 DNS Lookup
      │
      ▼
 Subdomain Enumeration
      │
      ▼
 Port Scanning
      │
      ▼
 HTTP Fingerprinting
      │
      ▼
 Report Generation
```

---

## Output

Results can be stored as JSON for further processing:

```json
{
  "domain": "example.com",
  "subdomains": [
    "api.example.com",
    "dev.example.com"
  ],
  "ports": [
    80,
    443
  ],
  "technologies": [
    "nginx",
    "php"
  ]
}
```

---

## Running Tests

```bash
pytest
```

---

## Roadmap

* [ ] CIDR/network range support
* [ ] Additional DNS record collection
* [ ] Screenshot capture for discovered web services
* [ ] Report generation (HTML/PDF)
* [ ] Plugin architecture
* [ ] Concurrent scanning improvements
* [ ] Containerized deployment

---

## Contributing

Contributions, bug reports, and suggestions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a pull request

---

## License

MIT License

See the LICENSE file for details.

---

## Disclaimer

This software is provided for educational and defensive security purposes only.

The author assumes no responsibility for misuse or damage caused by this software. Users are solely responsible for ensuring their activities comply with applicable laws, regulations, and authorization requirements.
