#!/usr/bin/env python3
"""
Medium-Complexity Network Scanner
Supports ICMP, TCP, ARP, and UDP probing with multi-threading.
"""

import argparse
import ipaddress
import json
import platform
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    from scapy.all import ARP as ScapyARP, Ether, srp  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class ScanMethod(Enum):
    ICMP = "icmp"
    TCP = "tcp"
    ARP = "arp"
    UDP = "udp"
    ALL = "all"


@dataclass
class HostResult:
    ip: str
    is_alive: bool
    methods: List[str]
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[int] = None
    response_time_ms: Optional[float] = None

    def __post_init__(self) -> None:
        if self.open_ports is None:
            self.open_ports = []


@dataclass
class ScanJob:
    job_id: str
    status: str
    network: str
    total_hosts: int
    completed_hosts: int
    active_hosts: int
    methods: List[str]
    ports: List[int]
    timeout: float
    threads: int
    resolve_hostnames: bool
    created_at: float
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    results: Optional[List[Dict[str, object]]] = None
    scanned_hosts: Optional[Dict[str, bool]] = None

    def __post_init__(self) -> None:
        if self.scanned_hosts is None:
            self.scanned_hosts = {}


class NetworkScanner:
    def __init__(self, timeout: float = 2.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: List[HostResult] = []
        self._lock = threading.Lock()

    def _ping_host(self, ip: str) -> Tuple[bool, float]:
        """ICMP echo request using system ping for cross-platform reliability."""
        system = platform.system().lower()

        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]

        try:
            start = time.time()
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 1,
            )
            elapsed = (time.time() - start) * 1000
            return result.returncode == 0, elapsed
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False, 0.0

    def _tcp_probe(self, ip: str, port: int = 80) -> Tuple[bool, float]:
        """TCP connect probe - often works when ICMP is blocked."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                start = time.time()
                result = sock.connect_ex((ip, port))
                elapsed = (time.time() - start) * 1000
                return result == 0, elapsed
        except socket.error:
            return False, 0.0

    def _udp_probe(self, ip: str, port: int = 53) -> Tuple[bool, float]:
        """UDP probe with a DNS-like payload."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                payload = (
                    b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                    b"\x07example\x03com\x00\x00\x01\x00\x01"
                )
                sock.sendto(payload, (ip, port))
                start = time.time()
                try:
                    sock.recvfrom(1024)
                    elapsed = (time.time() - start) * 1000
                    return True, elapsed
                except socket.timeout:
                    return False, 0.0
        except socket.error:
            return False, 0.0

    def _arp_request(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        ARP scan using system neighbor table output parsing.
        Returns (success, mac_address).
        """
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["arp", "-a", ip]
            elif system == "darwin":
                cmd = ["arp", "-n", ip]
            else:
                cmd = ["ip", "neigh", "show", ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            output = result.stdout

            if system == "windows":
                for line in output.split("\n"):
                    if ip in line:
                        for part in line.split():
                            if "-" in part and len(part) == 17:
                                return True, part.replace("-", ":").lower()
            else:
                if "lladdr" in output:
                    parts = output.split()
                    idx = parts.index("lladdr")
                    return True, parts[idx + 1].lower()
                for token in output.split():
                    if token.count(":") == 5 and len(token) == 17:
                        return True, token.lower()

            return False, None
        except Exception:
            return False, None

    def _arp_sweep(self, network: str) -> Dict[str, str]:
        """
        ARP sweep using Scapy for accurate LAN discovery.
        Returns a map of ip -> mac for responsive hosts.
        """
        if not SCAPY_AVAILABLE:
            return {}

        try:
            arp = ScapyARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            answered = srp(packet, timeout=self.timeout, verbose=0)[0]

            discovered: Dict[str, str] = {}
            for _, received in answered:
                discovered[str(received.psrc)] = str(received.hwsrc).lower()
            return discovered
        except Exception:
            return {}

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, TimeoutError):
            return None

    def _scan_single_host(
        self,
        ip: str,
        methods: List[ScanMethod],
        common_ports: Optional[List[int]],
        resolve_hostnames: bool,
        arp_cache: Optional[Dict[str, str]] = None,
    ) -> HostResult:
        """Scan a single host with specified methods."""
        detected_methods: List[str] = []
        open_ports: List[int] = []
        hostname: Optional[str] = None
        mac: Optional[str] = None
        best_time: Optional[float] = None

        if ScanMethod.ICMP in methods or ScanMethod.ALL in methods:
            alive, rtt = self._ping_host(ip)
            if alive:
                detected_methods.append("ICMP")
                best_time = rtt

        if ScanMethod.TCP in methods or ScanMethod.ALL in methods:
            ports_to_scan = common_ports if common_ports else [80, 443, 22, 445, 3389]
            for port in ports_to_scan:
                alive, rtt = self._tcp_probe(ip, port)
                if alive:
                    detected_methods.append(f"TCP:{port}")
                    open_ports.append(port)
                    if best_time is None or rtt < best_time:
                        best_time = rtt

        if ScanMethod.UDP in methods or ScanMethod.ALL in methods:
            alive, rtt = self._udp_probe(ip)
            if alive:
                detected_methods.append("UDP:53")
                if best_time is None:
                    best_time = rtt

        if ScanMethod.ARP in methods or ScanMethod.ALL in methods:
            if arp_cache and ip in arp_cache:
                arp_alive, arp_mac = True, arp_cache[ip]
            else:
                arp_alive, arp_mac = self._arp_request(ip)
            if arp_alive:
                detected_methods.append("ARP")
                mac = arp_mac

        is_alive = len(detected_methods) > 0
        if is_alive and resolve_hostnames:
            hostname = self._resolve_hostname(ip)

        return HostResult(
            ip=ip,
            is_alive=is_alive,
            methods=detected_methods,
            hostname=hostname,
            mac=mac,
            open_ports=open_ports,
            response_time_ms=best_time,
        )

    def scan_network(
        self,
        network: str,
        methods: Optional[List[ScanMethod]] = None,
        common_ports: Optional[List[int]] = None,
        progress_callback: Optional[Callable[[int, int, str, bool], None]] = None,
        resolve_hostnames: bool = True,
    ) -> List[HostResult]:
        """Scan an entire network CIDR (for example: 192.168.1.0/24)."""
        if methods is None:
            methods = [ScanMethod.ALL]

        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            total = len(hosts)
        except ValueError as exc:
            print(f"Invalid network: {exc}")
            return []

        print(f"Scanning {total} hosts in {network}...")
        print(f"Methods: {[m.value for m in methods]}")
        print(f"Timeout: {self.timeout}s | Threads: {self.max_threads}")
        print("-" * 50)

        arp_cache: Dict[str, str] = {}
        if ScanMethod.ARP in methods or ScanMethod.ALL in methods:
            arp_cache = self._arp_sweep(network)
            if arp_cache:
                print(f"ARP sweep discovered {len(arp_cache)} hosts")
            elif not SCAPY_AVAILABLE:
                print("Scapy not available; ARP sweep skipped (using ARP table fallback)")

        completed = 0
        results: List[HostResult] = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {
                executor.submit(
                    self._scan_single_host,
                    str(ip),
                    methods,
                    common_ports,
                    resolve_hostnames,
                    arp_cache,
                ): str(ip)
                for ip in hosts
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1

                try:
                    result = future.result()
                    is_alive = result.is_alive
                    if result.is_alive:
                        with self._lock:
                            results.append(result)
                except Exception as exc:
                    print(f"Error scanning {ip}: {exc}")
                    is_alive = False

                if progress_callback:
                    progress_callback(completed, total, ip, is_alive)
                elif completed % 50 == 0 or completed == total:
                    print(f"Progress: {completed}/{total} ({completed / total * 100:.1f}%)")

        results.sort(key=lambda item: ipaddress.ip_address(item.ip))
        self.results = results
        return results

    def print_results(self) -> None:
        """Display results in a formatted table."""
        if not self.results:
            print("\nNo active hosts found.")
            return

        print(f"\n{'=' * 70}")
        print(f"SCAN RESULTS: {len(self.results)} active hosts found")
        print(f"{'=' * 70}")
        print(f"{'IP Address':<16} {'Hostname':<25} {'Methods':<20} {'RTT(ms)':<10}")
        print(f"{'-' * 70}")

        for host in self.results:
            methods_str = ", ".join(host.methods[:2])
            if len(host.methods) > 2:
                methods_str += "..."
            hostname = host.hostname or "N/A"
            hostname = hostname[:24] if len(hostname) > 24 else hostname
            rtt = f"{host.response_time_ms:.1f}" if host.response_time_ms else "N/A"

            print(f"{host.ip:<16} {hostname:<25} {methods_str:<20} {rtt:<10}")

            if host.mac:
                print(f"  - MAC: {host.mac}")
            if host.open_ports:
                print(f"  - Open ports: {', '.join(map(str, host.open_ports))}")

        print(f"{'=' * 70}")


def _parse_ports(ports_raw: str) -> List[int]:
    ports: List[int] = []
    for token in ports_raw.split(","):
        token = token.strip()
        if not token:
            continue
        port = int(token)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port {port}: must be between 1 and 65535")
        ports.append(port)
    if not ports:
        raise ValueError("No valid ports provided")
    return ports


def _host_to_dict(host: HostResult) -> Dict[str, object]:
    return {
        "ip": host.ip,
        "is_alive": host.is_alive,
        "methods": host.methods,
        "hostname": host.hostname,
        "mac": host.mac,
        "vendor": host.vendor,
        "open_ports": host.open_ports,
        "response_time_ms": host.response_time_ms,
    }


JOBS: Dict[str, ScanJob] = {}
JOBS_LOCK = threading.Lock()


def _parse_method_names(method_names: List[str]) -> List[ScanMethod]:
    method_map = {
        "icmp": ScanMethod.ICMP,
        "tcp": ScanMethod.TCP,
        "arp": ScanMethod.ARP,
        "udp": ScanMethod.UDP,
        "all": ScanMethod.ALL,
    }
    parsed: List[ScanMethod] = []
    for name in method_names:
        method = method_map.get(name.lower())
        if method is None:
            raise ValueError(f"Unsupported scan method: {name}")
        parsed.append(method)
    if not parsed:
        raise ValueError("At least one scan method is required")
    return parsed


def _create_scan_job(
    network: str,
    methods: List[ScanMethod],
    ports: List[int],
    timeout: float,
    threads: int,
    resolve_hostnames: bool,
) -> str:
    net = ipaddress.ip_network(network, strict=False)
    total_hosts = len(list(net.hosts()))
    job_id = str(uuid.uuid4())
    job = ScanJob(
        job_id=job_id,
        status="queued",
        network=network,
        total_hosts=total_hosts,
        completed_hosts=0,
        active_hosts=0,
        methods=[method.value for method in methods],
        ports=ports,
        timeout=timeout,
        threads=threads,
        resolve_hostnames=resolve_hostnames,
        created_at=time.time(),
    )
    with JOBS_LOCK:
        JOBS[job_id] = job

    def _worker() -> None:
        scanner = NetworkScanner(timeout=timeout, max_threads=threads)
        with JOBS_LOCK:
            current = JOBS[job_id]
            current.status = "running"
            current.started_at = time.time()

        def _progress(completed: int, total: int, ip: str, is_alive: bool) -> None:
            with JOBS_LOCK:
                current = JOBS[job_id]
                current.completed_hosts = completed
                current.total_hosts = total
                current.scanned_hosts[ip] = is_alive
                current.active_hosts = sum(1 for value in current.scanned_hosts.values() if value)

        try:
            results = scanner.scan_network(
                network,
                methods=methods,
                common_ports=ports,
                progress_callback=_progress,
                resolve_hostnames=resolve_hostnames,
            )
            with JOBS_LOCK:
                current = JOBS[job_id]
                current.status = "completed"
                current.finished_at = time.time()
                current.results = [_host_to_dict(item) for item in results]
                current.active_hosts = len(results)
        except Exception as exc:
            with JOBS_LOCK:
                current = JOBS[job_id]
                current.status = "failed"
                current.finished_at = time.time()
                current.error = str(exc)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    return job_id


def _build_job_response(job: ScanJob) -> Dict[str, object]:
    progress_pct = 0.0
    if job.total_hosts > 0:
        progress_pct = (job.completed_hosts / job.total_hosts) * 100

    return {
        "job_id": job.job_id,
        "status": job.status,
        "network": job.network,
        "methods": job.methods,
        "ports": job.ports,
        "timeout": job.timeout,
        "threads": job.threads,
        "resolve_hostnames": job.resolve_hostnames,
        "total_hosts": job.total_hosts,
        "completed_hosts": job.completed_hosts,
        "active_hosts": job.active_hosts,
        "progress_pct": round(progress_pct, 2),
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error": job.error,
        "results": job.results if job.status == "completed" else None,
        "scanned_hosts": job.scanned_hosts,
    }


class ScannerApiHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(self, status_code: int, payload: Dict[str, object]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self._send_json(404, {"error": "File not found"})
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send_file(Path(__file__).with_name("index.html"))
            return

        if self.path == "/api/health":
            self._send_json(200, {"status": "ok"})
            return

        if self.path.startswith("/api/scan/"):
            job_id = self.path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if job is None:
                self._send_json(404, {"error": "Scan job not found"})
                return
            self._send_json(200, _build_job_response(job))
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self._send_json(404, {"error": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Invalid JSON payload"})
            return

        try:
            network = str(payload.get("network", "")).strip()
            timeout = float(payload.get("timeout", 2.0))
            threads = int(payload.get("threads", 100))
            resolve_hostnames = bool(payload.get("resolve_hostnames", False))

            raw_ports = payload.get(
                "ports",
                [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080],
            )
            if isinstance(raw_ports, str):
                ports = _parse_ports(raw_ports)
            else:
                ports = [int(port) for port in raw_ports]
                for port in ports:
                    if not 1 <= port <= 65535:
                        raise ValueError(f"Invalid port {port}: must be between 1 and 65535")
                if not ports:
                    raise ValueError("At least one TCP port is required")

            method_names = payload.get("methods", ["all"])
            if not isinstance(method_names, list):
                raise ValueError("methods must be a list")
            methods = _parse_method_names([str(name) for name in method_names])

            ipaddress.ip_network(network, strict=False)
            if timeout <= 0:
                raise ValueError("timeout must be greater than 0")
            if threads <= 0:
                raise ValueError("threads must be greater than 0")
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return

        try:
            job_id = _create_scan_job(
                network=network,
                methods=methods,
                ports=ports,
                timeout=timeout,
                threads=threads,
                resolve_hostnames=resolve_hostnames,
            )
        except Exception as exc:
            self._send_json(500, {"error": f"Failed to create scan job: {exc}"})
            return

        self._send_json(202, {"job_id": job_id})


def run_api_server(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), ScannerApiHandler)
    print(f"Scanner API server running at http://{host}:{port}")
    print("Open /index.html in your browser to use the UI")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Medium-Complexity Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.0/24
  python scanner.py 10.0.0.0/24 --method tcp --ports 22,80,443
  python scanner.py 192.168.1.0/24 --method icmp --timeout 1
        """,
    )

    parser.add_argument(
        "network",
        nargs="?",
        help="Network to scan (CIDR, e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--method",
        choices=["icmp", "tcp", "arp", "udp", "all"],
        default="all",
        help="Scan method to use (default: all)",
    )
    parser.add_argument(
        "--ports",
        default="21,22,23,25,53,80,110,139,143,443,445,3389,8080",
        help=(
            "Comma-separated TCP ports to scan "
            "(default: 21,22,23,25,53,80,110,139,143,443,445,3389,8080)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout per probe in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Max concurrent threads (default: 100)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Run HTTP API server and web UI",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface for server mode (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for server mode (default: 8765)",
    )

    args = parser.parse_args()

    if args.serve:
        run_api_server(host=args.host, port=args.port)
        return

    if not args.network:
        parser.error("network is required unless --serve is used")

    try:
        ports = _parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    method_map = {
        "icmp": [ScanMethod.ICMP],
        "tcp": [ScanMethod.TCP],
        "arp": [ScanMethod.ARP],
        "udp": [ScanMethod.UDP],
        "all": [ScanMethod.ALL],
    }
    methods = method_map[args.method]

    scanner = NetworkScanner(timeout=args.timeout, max_threads=args.threads)

    start_time = time.time()
    scanner.scan_network(
        args.network,
        methods=methods,
        common_ports=ports,
        resolve_hostnames=True,
    )
    scanner.print_results()

    duration = time.time() - start_time
    print(f"\nScan completed in {duration:.2f} seconds")


if __name__ == "__main__":
    main()
