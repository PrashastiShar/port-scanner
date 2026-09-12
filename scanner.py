import socket
import argparse
import datetime
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                3306, 3389, 5432, 6379, 8080, 8443, 27017]


def scan_port(host, port, timeout=0.5):
    """Return True if the port is open on host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except socket.error:
        return False


def scan_host(host, ports, workers=100):
    """Scan a list of ports concurrently. Returns list of open ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(lambda p: (p, scan_port(host, p)), ports)
        for port, is_open in results:
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


def generate_html(host, open_ports, output="report.html"):
    """Write an HTML report of the scan."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = "\n".join(
        f"<tr><td>{p}</td><td>{socket.getservbyport(p, 'tcp') if _has_service(p) else 'unknown'}</td><td>open</td></tr>"
        for p in open_ports
    ) or "<tr><td colspan='3'>No open ports found.</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Port Scan Report - {host}</title>
  <style>
    body {{ font-family: sans-serif; max-width: 700px; margin: 40px auto; }}
    h1 {{ color: #2c3e50; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #2c3e50; color: white; }}
    .meta {{ color: #666; font-size: 0.9em; }}
  </style>
</head>
<body>
  <h1>Port Scan Report</h1>
  <p class="meta">Target: <strong>{host}</strong><br>Scanned at: {now}</p>
  <table>
    <tr><th>Port</th><th>Service</th><th>Status</th></tr>
    {rows}
  </table>
</body>
</html>"""

    with open(output, "w") as f:
        f.write(html)
    return output


def _has_service(port):
    try:
        socket.getservbyport(port, "tcp")
        return True
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description="Simple Python port scanner.")
    parser.add_argument("host", help="Target host (e.g. 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="common",
                        help="'common' or a range like 1-1024")
    parser.add_argument("-o", "--output", default="report.html",
                        help="Output HTML file")
    args = parser.parse_args()

    if args.ports == "common":
        ports = COMMON_PORTS
    else:
        start, end = map(int, args.ports.split("-"))
        ports = list(range(start, end + 1))

    print(f"[*] Scanning {args.host} ({len(ports)} ports)...")
    open_ports = scan_host(args.host, ports)

    report = generate_html(args.host, open_ports, args.output)
    print(f"[+] Done. {len(open_ports)} open port(s). Report: {report}")


if __name__ == "__main__":
    main()
