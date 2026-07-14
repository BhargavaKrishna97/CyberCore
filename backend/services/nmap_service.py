import subprocess
import re

def run_nmap_scan(target: str, ports: str = "1-6000") -> dict:
    """
    Run Nmap scan and parse open ports.
    """

    try:
        cmd = [
            "nmap",
	    "-Pn",
	    "-sT",
            "-sV",
            "--open",
            "-p",
            ports,
            target
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False
        )

        output = result.stdout
        print("="*50)
        print("COMMAND:", " ".join(cmd))
        print("="*50)
        print("RETURN CODE:",result.returncode)
        print("=" * 50)
        print("STDOUT:")
        print(output)
        print("="*50)

        print("STDERR:")
        print(result.stderr)
        print("="*50)

        scan_results = []

        for line in output.splitlines():
            print("LINE:", repr(line))
            match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)

            if match:
                print("MATCH FOUND:", match.groups())
                scan_results.append({
                    "port": match.group(1),
                    "service": match.group(2)
                })

        return {
            "target": target,
            "scan_results": scan_results,
            "raw_output": output
        }

    except Exception as e:
        return {
            "error": str(e),
            "target": target
        }
