import nmap
import json

def run_nmap_scan(target: str, ports: str = "1-1024") -> dict:
    """
    Run an nmap port scan on the target.
    target: IP or hostname (e.g. '192.168.1.1')
    ports:  port range (e.g. '1-1024' or '80,443,8080')
    """
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=target, ports=ports, arguments="-sV --open")
    except Exception as e:
        return {"error": str(e), "target": target}

    results = []
    for host in scanner.all_hosts():
        host_data = {
            "host":     host,
            "hostname": scanner[host].hostname(),
            "state":    scanner[host].state(),
            "protocols": {}
        }

        for proto in scanner[host].all_protocols():
            ports_info = {}
            for port, data in scanner[host][proto].items():
                ports_info[port] = {
                    "state":   data["state"],
                    "name":    data.get("name", ""),
                    "product": data.get("product", ""),
                    "version": data.get("version", ""),
                }
            host_data["protocols"][proto] = ports_info

        results.append(host_data)

    return {"target": target, "scan_results": results}
