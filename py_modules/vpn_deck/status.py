"""
ConnectionStatus - What the panel shows under an active tunnel: exit address, tunnel address, traffic
"""

import os
import subprocess
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import decky

from ._utils import clean_env
from .network_watch import parse_dump

# Cloudflare's trace answers with the address it sees and its country, nothing else to trust or parse.
TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
EXIT_REFRESH_SEC = 120
EXIT_RETRY_SEC = 15
NET_DIR = "/sys/class/net"


def parse_trace(text: str) -> Optional[Dict[str, str]]:
    fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    if not fields.get("ip"):
        return None
    return {"ip": fields["ip"], "country": fields.get("loc", "")}


def parse_ipv4_address(output: str) -> Optional[str]:
    """First address from `ip -4 -o addr show dev <iface>`."""
    tokens = output.split()
    if "inet" in tokens:
        i = tokens.index("inet") + 1
        if i < len(tokens):
            return tokens[i].split("/", 1)[0]
    return None


class ConnectionStatus:
    def __init__(self, service_manager, net_dir: str = NET_DIR,
                 fetch_exit: Optional[Callable[[], Optional[Dict[str, str]]]] = None):
        self.service_manager = service_manager
        self.net_dir = net_dir
        self._fetch_exit = fetch_exit or self._fetch_trace
        self._exits: Dict[str, dict] = {}
        self._pending = set()
        self._active = set()
        self._lock = threading.Lock()

    def _fetch_trace(self) -> Optional[Dict[str, str]]:
        try:
            result = subprocess.run(["curl", "-s", "--max-time", "8", TRACE_URL], capture_output=True,
                                    text=True, timeout=12, env=clean_env())
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        return parse_trace(result.stdout) if result.returncode == 0 else None

    def _refresh_exit(self, interface: str, requested_at: float) -> None:
        info = None
        try:
            info = self._fetch_exit()
        except Exception as e:
            decky.logger.warning(f"{interface}: exit address check failed: {e}")
        with self._lock:
            self._pending.discard(interface)
            # The tunnel went down while curl was running: its answer is already stale.
            if interface not in self._active:
                return
            if info is not None:
                self._exits[interface] = dict(info, checked_at=requested_at)
            else:
                previous = self._exits.get(interface, {"ip": None, "country": ""})
                # Keep what was known, but look again soon rather than in two minutes.
                self._exits[interface] = dict(previous, checked_at=requested_at - EXIT_REFRESH_SEC + EXIT_RETRY_SEC)

    def exit_info(self, interface: str, now: float) -> Optional[dict]:
        """Cached exit address; a stale or missing one is refreshed in the background."""
        with self._lock:
            entry = self._exits.get(interface)
            stale = entry is None or now - entry["checked_at"] >= EXIT_REFRESH_SEC
            if stale and interface not in self._pending:
                self._pending.add(interface)
                threading.Thread(target=self._refresh_exit, args=(interface, now), daemon=True).start()
        return entry

    def counters(self, interface: str) -> Optional[Dict[str, int]]:
        try:
            values = {}
            for name in ("rx_bytes", "tx_bytes"):
                with open(os.path.join(self.net_dir, interface, "statistics", name)) as f:
                    values[name] = int(f.read().strip())
            return values
        except (OSError, ValueError):
            return None

    def _awg_details(self, interface: str, now: float) -> Tuple[Optional[str], Optional[int]]:
        rc, out, _ = self.service_manager.run_command(["ip", "-4", "-o", "addr", "show", "dev", interface])
        address = parse_ipv4_address(out) if rc == 0 else None
        handshake_age = None
        awg = self.service_manager.binary_manager.get_binary_path("awg")
        if awg:
            rc, out, _ = self.service_manager.run_command([awg, "show", interface, "dump"])
            if rc == 0:
                _, handshakes, _ = parse_dump(out)
                stamps = [int(v) for v in handshakes.values() if v.isdigit() and int(v) > 0]
                if stamps:
                    handshake_age = max(0, int(now - max(stamps)))
        return address, handshake_age

    def snapshot(self, tunnels: Iterable[Tuple[str, str, str]], now: Optional[float] = None) -> List[dict]:
        """Status of (config name, interface, type) tunnels for the panel."""
        now = time.time() if now is None else now
        tunnels = list(tunnels)
        with self._lock:
            self._active = {interface for _, interface, _ in tunnels}
            # A tunnel that went down checks its exit again when it comes back.
            for interface in [i for i in self._exits if i not in self._active]:
                del self._exits[interface]
        result = []
        for name, interface, kind in tunnels:
            address, handshake_age = self._awg_details(interface, now) if kind == "awg" else (None, None)
            exit_entry = self.exit_info(interface, now)
            counters = self.counters(interface) or {}
            result.append({
                "name": name,
                "interface": interface,
                "type": kind,
                "address": address,
                "handshake_age": handshake_age,
                "exit_ip": exit_entry.get("ip") if exit_entry else None,
                "exit_country": exit_entry.get("country", "") if exit_entry else "",
                "rx_bytes": counters.get("rx_bytes"),
                "tx_bytes": counters.get("tx_bytes"),
                "sampled_at": now,
            })
        return result
