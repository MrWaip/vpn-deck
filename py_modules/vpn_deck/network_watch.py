"""
NetworkWatch - Keeps managed tunnels working after suspend/resume and network changes
"""

import asyncio
import ipaddress
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

import decky

from .service_manager import MANAGED_PREFIX

CHECK_INTERVAL_SEC = 15
# With keepalive a healthy peer rehandshakes every ~2 min; it can briefly pass 180 s
# when the server initiated the session, which is what STALE_GRACE_SEC absorbs.
STALE_HANDSHAKE_SEC = 180
# Time WireGuard gets to recover by itself (after resume or a re-pin) before a restart.
STALE_GRACE_SEC = 60
RESTART_BACKOFF_SEC = 300
# How often to retry `up` for a tunnel whose restart left it down.
RETRY_UP_SEC = 60
# Written by the endpoint-direct-route patch in bin/awg-quick.
ENDPOINT_ROUTE_STATE_DIR = "/var/run/awg-quick"

_NON_UNICAST = {"unreachable", "blackhole", "prohibit", "throw", "local",
                "broadcast", "anycast", "multicast", "nat"}

ErrorSink = Callable[[str, str, str, dict], None]


@dataclass(frozen=True)
class Route:
    prefixlen: int
    gateway: Optional[str]
    dev: Optional[str]
    metric: int = 0

    def describe(self) -> str:
        return f"{self.gateway or 'on-link'} dev {self.dev}"


def _host_bits(ip: str) -> int:
    return 128 if ":" in ip else 32


def _field(tokens: List[str], name: str) -> Optional[str]:
    if name in tokens:
        i = tokens.index(name) + 1
        if i < len(tokens):
            return tokens[i]
    return None


def parse_routes(output: str) -> List[Route]:
    """Parses `ip route show` output. Skips non-unicast, dead and linkdown routes."""
    routes = []
    for line in output.splitlines():
        tokens = line.split()
        # Indented lines are multipath nexthops of the previous route.
        if not tokens or line[0].isspace():
            continue
        if tokens[0] == "unicast":
            tokens = tokens[1:]
        if tokens[0] in _NON_UNICAST or "dead" in tokens or "linkdown" in tokens:
            continue
        dst = tokens[0]
        if dst == "default":
            prefixlen = 0
        elif "/" in dst:
            prefixlen = int(dst.split("/", 1)[1])
        else:
            prefixlen = _host_bits(dst)
        metric = _field(tokens, "metric")
        routes.append(Route(
            prefixlen=prefixlen,
            gateway=_field(tokens, "via"),
            dev=_field(tokens, "dev"),
            metric=int(metric) if metric and metric.isdigit() else 0,
        ))
    return routes


def find_pin(routes: List[Route], host_bits: int) -> Optional[Route]:
    """Host route to the endpoint from `ip route show match <ip>/<bits>` output."""
    pins = [r for r in routes if r.prefixlen == host_bits]
    return min(pins, key=lambda r: r.metric) if pins else None


def underlay_route(routes: List[Route], host_bits: int, tunnel_devs: Iterable[str]) -> Optional[Route]:
    """Route the kernel would use for the endpoint without its pinned host route.

    Longest prefix, then lowest metric, among main-table routes that cover the
    endpoint, ignoring the pin itself and routes through tunnel interfaces.
    None means offline, or a route (multipath) that cannot be re-pinned as is.
    """
    tunnel_devs = set(tunnel_devs)
    candidates = [r for r in routes if r.prefixlen < host_bits and r.dev not in tunnel_devs]
    if not candidates:
        return None
    best = max(candidates, key=lambda r: (r.prefixlen, -r.metric))
    return best if best.dev else None


def decide_repin(pin: Optional[Route], underlay: Optional[Route]) -> Optional[Route]:
    """Returns the route to re-pin the endpoint through, or None to leave it alone.

    A missing pin counts as stale: the kernel flushes it together with the old
    address on the interface, while the state file still expects it.
    """
    if underlay is None or underlay.gateway is None:
        return None
    if pin is not None and (pin.gateway, pin.dev) == (underlay.gateway, underlay.dev):
        return None
    return underlay


def parse_dump(output: str) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """Parses `awg show <iface> dump` into {public_key: endpoint}, {..: latest handshake}, {..: keepalive}.

    The first line describes the interface and its columns differ between AWG
    versions; peer lines keep the WireGuard order: public key, preshared key,
    endpoint, allowed IPs, latest handshake, rx, tx, persistent keepalive.
    """
    endpoints, handshakes, keepalives = {}, {}, {}
    for line in output.splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) < 8:
            continue
        key = cols[0]
        endpoints[key], handshakes[key], keepalives[key] = cols[2], cols[4], cols[7]
    return endpoints, handshakes, keepalives


def parse_endpoint_ip(endpoint: str) -> Optional[str]:
    """'1.2.3.4:51820' or '[2001:db8::1]:51820' -> IP; '(none)' -> None."""
    host, sep, port = endpoint.rpartition(":")
    if not sep or not port.isdigit():
        return None
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


def parse_state_file(content: str) -> Set[str]:
    """Endpoint IPs pinned by awg-quick, from lines like '-4 203.0.113.7/32'."""
    pinned = set()
    for line in content.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            pinned.add(str(ipaddress.ip_address(parts[1].split("/", 1)[0])))
        except ValueError:
            continue
    return pinned


def handshake_age(endpoints: Dict[str, str], handshakes: Dict[str, str],
                  keepalives: Dict[str, str], now: float) -> Optional[float]:
    """Oldest handshake age among peers with an endpoint and persistent keepalive.

    Peers without keepalive may legitimately stay silent, and 0 means the peer
    never completed a handshake since the interface came up: both give None.
    """
    ages = []
    for key in endpoints:
        if keepalives.get(key, "off") in ("off", "0"):
            continue
        value = handshakes.get(key, "0")
        if value.isdigit() and int(value) > 0:
            ages.append(max(0.0, now - int(value)))
    return max(ages) if ages else None


@dataclass
class IfaceState:
    stale_since: Optional[float] = None
    last_restart: Optional[float] = None

    def should_restart(self, age: Optional[float], online: bool, repinned: bool, now: float) -> bool:
        """Tracks how long the handshake has been stale and decides on a restart."""
        if age is None or age < STALE_HANDSHAKE_SEC or not online:
            self.stale_since = None
            return False
        if repinned or self.stale_since is None:
            self.stale_since = now
            return False
        if now - self.stale_since < STALE_GRACE_SEC:
            return False
        if self.last_restart is not None and now - self.last_restart < RESTART_BACKOFF_SEC:
            return False
        return True


class NetworkWatch:
    def __init__(self, service_manager, on_error: Optional[ErrorSink] = None,
                 state_dir: str = ENDPOINT_ROUTE_STATE_DIR):
        self.service_manager = service_manager
        self.on_error = on_error
        self.state_dir = state_dir
        self._states: Dict[str, IfaceState] = {}
        self._reported: Dict[Tuple[str, str], str] = {}
        # Tunnels our restart left down: interface -> time of the last `up` attempt.
        self._pending_up: Dict[str, float] = {}
        self._stopping = threading.Event()
        self._last_tick_error: Optional[str] = None
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.get_running_loop().create_task(self._loop())

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        self._stopping.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # A tick already running in its thread cannot be cancelled: let a restart
        # finish rather than leave the tunnel down when the plugin unloads.
        await asyncio.to_thread(self._wait_idle)

    def forget(self, iface: Optional[str] = None) -> None:
        """The user started or stopped a tunnel by hand: drop pending `up` retries for it.

        Call it under ServiceManager.lock together with that start or stop.
        """
        if iface is None:
            self._pending_up.clear()
        else:
            self._pending_up.pop(iface, None)

    def _wait_idle(self) -> None:
        with self.service_manager.lock:
            pass

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(CHECK_INTERVAL_SEC)
            # A worker thread keeps a slow restart from stalling the panel's RPCs;
            # ServiceManager.lock keeps it from interleaving with a user's toggle.
            try:
                await asyncio.to_thread(self.tick)
                self._last_tick_error = None
            except Exception as e:
                if str(e) != self._last_tick_error:
                    decky.logger.error(f"Network watch tick failed: {type(e).__name__}: {e}")
                self._last_tick_error = str(e)

    def _run(self, cmd: list):
        return self.service_manager.run_command(cmd)

    def tick(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        awg = self.service_manager.binary_manager.get_binary_path("awg")
        if awg is None:
            return
        ifaces = self.service_manager.list_interfaces()
        self._forget_gone(set(ifaces) | set(self._pending_up))
        for iface in ifaces:
            if iface.startswith(MANAGED_PREFIX) and not self._stopping.is_set():
                with self.service_manager.lock:
                    self._check_interface(awg, iface, ifaces, now)
        if self._pending_up:
            # Listed again: a restart in this very tick may have left a tunnel down.
            self._retry_pending_up(set(self.service_manager.list_interfaces()), now)

    def _forget_gone(self, keep: Set[str]) -> None:
        """A tunnel that went down starts from scratch when it comes back up."""
        for iface in [i for i in self._states if i not in keep]:
            del self._states[iface]
        for key in [k for k in self._reported if k[0] not in keep]:
            del self._reported[key]

    def _retry_pending_up(self, active: Set[str], now: float) -> None:
        for iface, last_try in list(self._pending_up.items()):
            if iface in active:
                self._pending_up.pop(iface, None)
                continue
            if now - last_try < RETRY_UP_SEC or self._stopping.is_set():
                continue
            with self.service_manager.lock:
                # forget() may have run while this thread waited for the lock.
                if iface not in self._pending_up:
                    continue
                self._pending_up[iface] = now
                start = self.service_manager.start_interface(iface)
            if start["success"]:
                self._pending_up.pop(iface, None)
                self._reported.pop((iface, "restart"), None)
                decky.logger.info(f"{iface}: tunnel is back up after a failed restart")
            else:
                self._report_up_failure(iface, start["error"])

    def _peers(self, awg: str, iface: str) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        rc, out, _ = self._run([awg, "show", iface, "dump"])
        return parse_dump(out) if rc == 0 else ({}, {}, {})

    def _pinned_endpoints(self, iface: str) -> Set[str]:
        try:
            with open(os.path.join(self.state_dir, f"{iface}.endpoint-routes")) as f:
                return parse_state_file(f.read())
        except OSError:
            return set()

    def _check_interface(self, awg: str, iface: str, tunnel_devs: List[str], now: float) -> None:
        raw_endpoints, handshakes, keepalives = self._peers(awg, iface)
        endpoints = {}
        for key, value in raw_endpoints.items():
            ip = parse_endpoint_ip(value)
            if ip:
                endpoints[key] = ip
        if not endpoints:
            return

        pinned = self._pinned_endpoints(iface)
        online = repinned = False
        for ip in sorted(set(endpoints.values())):
            bits = _host_bits(ip)
            family = "-6" if bits == 128 else "-4"
            rc, out, _ = self._run(["ip", family, "route", "show", "table", "main", "match", f"{ip}/{bits}"])
            if rc != 0:
                continue
            routes = parse_routes(out)
            underlay = underlay_route(routes, bits, tunnel_devs)
            online = online or underlay is not None
            # Only pins that awg-quick recorded are ours to move; down deletes them by prefix.
            if ip not in pinned:
                continue
            pin = find_pin(routes, bits)
            target = decide_repin(pin, underlay)
            if target is not None and self._repin(iface, family, f"{ip}/{bits}", pin, target):
                repinned = True

        age = handshake_age(endpoints, handshakes, keepalives, now)
        state = self._states.setdefault(iface, IfaceState())
        if state.should_restart(age, online, repinned, now):
            state.last_restart = now
            state.stale_since = None
            self._restart(iface, age, now)

    def _repin(self, iface: str, family: str, cidr: str, pin: Optional[Route], target: Route) -> bool:
        rc, _, err = self._run(["ip", family, "route", "replace", cidr,
                                "via", target.gateway, "dev", target.dev])
        if rc != 0:
            self._report(iface, "repin", f"Не удалось перевести маршрут до VPN-сервера на новую сеть: {err or f'rc={rc}'}")
            return False
        old = pin.describe() if pin else "missing"
        decky.logger.info(f"{iface}: re-pinned endpoint route {old} -> {target.describe()}")
        self._reported.pop((iface, "repin"), None)
        return True

    def _restart(self, iface: str, age: Optional[float], now: float) -> None:
        decky.logger.info(f"{iface}: latest handshake {int(age or 0)}s ago, restarting the tunnel")
        stop = self.service_manager.stop_interface(iface)
        if not stop["success"]:
            self._report(iface, "restart", f"Не удалось остановить зависший туннель: {stop['error']}")
            return
        start = self.service_manager.start_interface(iface)
        if not start["success"]:
            self._pending_up[iface] = now
            self._report_up_failure(iface, start["error"])
            return
        self._reported.pop((iface, "restart"), None)

    def _report_up_failure(self, iface: str, error: str) -> None:
        self._report(iface, "restart",
                     f"Зависший туннель остановлен, но не поднялся снова, пробую раз в минуту: {error}")

    def _report(self, iface: str, op: str, message: str) -> None:
        """Adds to the error history once per distinct failure, not on every tick."""
        if self._reported.get((iface, op)) == message:
            return
        self._reported[(iface, op)] = message
        if self.on_error is not None:
            self.on_error(f"network_watch.{op}", "NetworkWatchError", message, {"interface": iface})
        else:
            decky.logger.error(f"{iface}: {message}")
