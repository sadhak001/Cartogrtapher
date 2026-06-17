import shutil
import nmap


COMMON_PORTS = (
    "21,22,23,25,53,80,110,139,143,"
    "443,445,993,995,1723,3306,3389,"
    "5900,8080,8443"
)


def scan_target(target, ports=COMMON_PORTS, arguments="-sV -T4"):
    """
    Scan a target for open ports and attempt service/version detection.
    """

    if shutil.which("nmap") is None:
        return {
            "error": "Nmap is not installed or not available in PATH."
        }

    try:
        scanner = nmap.PortScanner()

        scanner.scan(
            hosts=target,
            ports=ports,
            arguments=arguments,
        )

    except nmap.PortScannerError as e:
        return {"error": f"Nmap error: {e}"}

    except Exception as e:
        return {"error": str(e)}

    hosts = scanner.all_hosts()

    print("DEBUG HOSTS:", hosts)

    if not hosts:
        return {
            "error": (
                "Host did not respond, appears down, "
                "or blocked the scan."
            )
        }

    host_data = scanner[hosts[0]]

    results = {}

    for proto in host_data.all_protocols():

        ports_data = host_data[proto]

        for port, info in ports_data.items():

            results[port] = {
                "protocol": proto,
                "state": info.get("state", ""),
                "service": info.get("name", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
            }

    if not results:
        return {
            "error": (
                "Host is up, but no open ports were found "
                "within the requested port range."
            )
        }

    return results