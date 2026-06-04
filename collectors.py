import ipaddress
import random
import socket
import struct
import subprocess
import threading
import time
from collections import Counter

from helpers import merge_proto, normalize_error_text, parse_ss_endpoint, simulated_proto_for_ip
from settings import RadarSettings


class PacketSniffer(threading.Thread):
    def __init__(self, settings: RadarSettings, iface: str | None = None):
        super().__init__(daemon=True)
        self.settings = settings
        self.iface = iface
        self.running = threading.Event()
        self.running.set()
        self.lock = threading.Lock()
        self.counter = Counter()
        self.local_addrs = set(self._get_local_ips())
        self._supported = True
        self.sock = None
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if iface:
                self.sock.bind((iface, 0))
        except PermissionError:
            self._supported = False
        except OSError:
            self._supported = False

    def _get_local_ips(self) -> list[str]:
        addrs: set[str] = {"127.0.0.1"}
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
                if family == socket.AF_INET:
                    addrs.add(sockaddr[0])
        except OSError:
            pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(("8.8.8.8", 80))
                addrs.add(probe.getsockname()[0])
        except OSError:
            pass
        return sorted(addrs)

    def run(self) -> None:
        if not self._supported or self.sock is None:
            return
        self.sock.settimeout(1.0)
        while self.running.is_set():
            try:
                raw, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(raw) < 34:
                continue
            eth_proto = struct.unpack("!H", raw[12:14])[0]
            if eth_proto != 0x0800:
                continue
            ip_header = raw[14:34]
            ihl = (ip_header[0] & 0x0F) * 4
            if ihl < 20:
                continue
            src = socket.inet_ntoa(ip_header[12:16])
            dst = socket.inet_ntoa(ip_header[16:20])
            if src in self.local_addrs:
                remote = dst
            elif dst in self.local_addrs:
                remote = src
            else:
                remote = src
            with self.lock:
                self.counter[remote] += 1

    def snapshot_and_reset(self) -> dict[str, int]:
        with self.lock:
            snapshot = dict(self.counter)
            self.counter.clear()
        return snapshot

    def stop(self) -> None:
        self.running.clear()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass


class SimulationCollector:
    def __init__(self, settings: RadarSettings, hosts: int = 12, max_rate: int = 200):
        self.settings = settings
        self.hosts = hosts
        self.max_rate = max_rate
        self._hosts = [f"192.0.2.{index + 1}" for index in range(hosts)]
        self._lock = threading.Lock()
        self._rng = random.Random(12345)
        self._counts = Counter()
        self._last = time.time() - settings.sample_interval
        self._supported = True
        self._simulated = True

    def _tick(self) -> None:
        now = time.time()
        delta = max(0.001, now - self._last)
        self._last = now
        for host in self._hosts:
            rate = abs(int(self._rng.gauss(self.max_rate / max(1, len(self._hosts)), 5)))
            self._counts[host] += int(rate * delta)

    def snapshot_and_reset(self) -> dict[str, int]:
        with self._lock:
            self._tick()
            snapshot = dict(self._counts)
            self._counts.clear()
        return snapshot

    def snapshot(self) -> tuple[dict[str, dict[str, int | str]], dict[str, int | str | None]]:
        with self._lock:
            self._tick()
            ip_stats: dict[str, dict[str, int | str]] = {}
            for ip, count in self._counts.items():
                ip_stats[ip] = {
                    "connections": max(1, int(count // max(1, len(self._hosts)))),
                    "proto": simulated_proto_for_ip(ip),
                }
            pkt_delta = sum(self._counts.values())
        meta = {
            "pkt_delta": pkt_delta,
            "total_conns": sum(int(item["connections"]) for item in ip_stats.values()),
            "ss_error": None,
            "collector": "simulation",
        }
        return ip_stats, meta


class ConnectionScanner:
    proc_tables = (
        ("/proc/net/tcp", "TCP", 4),
        ("/proc/net/udp", "UDP", 4),
        ("/proc/net/tcp6", "TCP", 16),
        ("/proc/net/udp6", "UDP", 16),
    )

    def __init__(self, settings: RadarSettings, iface: str | None = None):
        self.settings = settings
        self.iface = iface
        self.prev_iface_counts = None
        self.prev_ts = time.time()
        self.last_error = None

    def _read_proc_net_dev(self) -> dict[str, dict[str, int]]:
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError:
            return {}
        data: dict[str, dict[str, int]] = {}
        for line in lines[2:]:
            parts = line.strip().split()
            if len(parts) < 17:
                continue
            iface = parts[0].strip(":")
            if self.iface and iface != self.iface:
                continue
            data[iface] = {"rx": int(parts[2]), "tx": int(parts[10])}
        return data

    def _decode_proc_ip(self, hex_host: str, size: int) -> str | None:
        try:
            raw = bytes.fromhex(hex_host)
            if size == 4:
                raw = raw[::-1]
            else:
                raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return None

    def _read_proc_socket_tables(self) -> dict[str, dict[str, int | str]]:
        ip_stats: dict[str, dict[str, int | str]] = {}
        for path, proto, size in self.proc_tables:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    lines = handle.readlines()[1:]
            except OSError:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 3:
                    continue
                remote = parts[2]
                hex_host = remote.split(":", 1)[0]
                ip = self._decode_proc_ip(hex_host, size)
                if not ip:
                    continue
                try:
                    address = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if address.is_unspecified:
                    continue
                entry = ip_stats.setdefault(ip, {"connections": 0, "proto": proto})
                entry["connections"] = int(entry["connections"]) + 1
                entry["proto"] = merge_proto(str(entry["proto"]), proto)
        return ip_stats

    def snapshot(self) -> tuple[dict[str, dict[str, int | str]], dict[str, int | str | None]]:
        ip_stats: dict[str, dict[str, int | str]] = {}
        collector = "ss"
        try:
            proc = subprocess.run(
                ["ss", "-H", "-n", "-t", "-u"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1.0,
                check=False,
            )
            self.last_error = normalize_error_text(proc.stderr)
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                proto = parts[0].upper()
                if proto not in {"TCP", "UDP"}:
                    continue
                ip = parse_ss_endpoint(parts[-1])
                if not ip:
                    continue
                entry = ip_stats.setdefault(ip, {"connections": 0, "proto": proto})
                entry["connections"] = int(entry["connections"]) + 1
                entry["proto"] = merge_proto(str(entry["proto"]), proto)
        except (subprocess.SubprocessError, OSError):
            self.last_error = "ss invocation failed"

        if not ip_stats:
            fallback = self._read_proc_socket_tables()
            if fallback:
                ip_stats = fallback
                collector = "proc"
                self.last_error = (
                    f"{self.last_error} | using /proc fallback" if self.last_error else "using /proc fallback"
                )

        now = time.time()
        current = self._read_proc_net_dev()
        pkt_delta = 0
        if self.prev_iface_counts is not None:
            for iface, counts in current.items():
                previous = self.prev_iface_counts.get(iface)
                if not previous:
                    continue
                delta_rx = max(0, counts["rx"] - previous["rx"])
                delta_tx = max(0, counts["tx"] - previous["tx"])
                pkt_delta += delta_rx + delta_tx
        self.prev_iface_counts = current
        self.prev_ts = now

        meta = {
            "pkt_delta": pkt_delta,
            "total_conns": sum(int(item["connections"]) for item in ip_stats.values()),
            "ss_error": self.last_error,
            "collector": collector,
        }
        return ip_stats, meta
