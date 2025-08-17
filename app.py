import socket
import ipaddress
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import subprocess
import platform
from tabulate import tabulate

# Load config
with open("config.yml", "r") as f:
    config = yaml.safe_load(f)

ip_ranges = config.get("ip_ranges", [])
gateways = set(config.get("gateways", []))  # whitelist, skip scanning
tcp_ports = config.get("tcp_ports", [])
udp_ports = config.get("udp_ports", [])
timeout = config.get("timeout", 10)
ping_count = config.get("ping_count", 1)
max_threads = config.get("threads", 20)

succeed_ips = []
failed_ips = []
results_table = []
lock = Lock()

def icmp_ping(ip):
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        result = subprocess.run(
            ["ping", param_count, str(ping_count), param_timeout, str(timeout), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False

def tcp_probe(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except:
        return False

def udp_probe(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"Test", (ip, port))
        sock.recvfrom(1024)
        sock.close()
        return True
    except:
        return False

def scan_ip(ip):
    if ip in gateways:  # Skip gateway/whitelist
        return None

    alive = icmp_ping(ip)
    tcp_status = {port: tcp_probe(ip, port) for port in tcp_ports} if alive else {}
    udp_status = {port: udp_probe(ip, port) for port in udp_ports} if alive else {}

    with lock:
        if alive:
            succeed_ips.append(ip)
        else:
            failed_ips.append(ip)

        results_table.append({
            "IP": ip,
            "Status": "Online" if alive else "Offline",
            **{f"TCP {p}": "Open" if tcp_status.get(p) else "Closed" for p in tcp_ports},
            **{f"UDP {p}": "Open" if udp_status.get(p) else "Closed" for p in udp_ports}
        })

    return alive

def main():
    all_ips = [str(ip) for ip_range in ip_ranges for ip in ipaddress.IPv4Network(ip_range).hosts()]

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            future.result()  # results stored in results_table

    # Print table
    if results_table:
        print("\n=== Scan Results ===")
        print(tabulate(results_table, headers="keys", tablefmt="grid"))

    # Summary
    print("\n=== Summary ===")
    print(f"Succeed IPs ({len(succeed_ips)}): {succeed_ips}")
    print(f"Failed IPs ({len(failed_ips)}): {failed_ips}")

    # Save to files
    with open("online-ip.txt", "w") as f:
        for ip in succeed_ips:
            f.write(ip + "\n")

    with open("offline-ip.txt", "w") as f:
        for ip in failed_ips:
            f.write(ip + "\n")

    print("\nLogs saved to 'online-ip.txt' and 'offline-ip.txt'.")

if __name__ == "__main__":
    main()
