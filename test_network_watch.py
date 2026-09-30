#!/usr/bin/env python3
"""
Unit tests for the network watcher (endpoint route re-pin and stuck tunnel restart)
"""

import asyncio
import os
import shutil
import sys
import tempfile
import threading
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_modules"))
_here = os.path.dirname(os.path.abspath(__file__))
sys.modules.setdefault("decky", types.SimpleNamespace(
    logger=types.SimpleNamespace(info=print, debug=print, warning=print, error=print),
    DECKY_PLUGIN_DIR=_here, DECKY_PLUGIN_LOG_DIR=os.path.join(_here, "logs")))

from vpn_deck import network_watch as nw
from vpn_deck.network_watch import (
    IfaceState, NetworkWatch, Route, decide_repin, find_pin, handshake_age, parse_endpoint_ip,
    parse_dump, parse_routes, parse_state_file, underlay_route,
)


KEY = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
KEY2 = "YAnz5TF+lXXJte14tji3zlMNftft3UL32bbjzVEwPBs="
ENDPOINT = "203.0.113.7"
# `awg show <iface> dump` interface line of amneziawg-tools 3.1: its columns vary between versions.
DUMP_INTERFACE = "\t".join([
    "(none)", "PUBKEY=", "0", "4", "40", "70", "0", "0", "0", "0",
    "1-2", "3-4", "5-6", "7-8", "<r 2><b 0x858000010001> <t>", "(null)", "(null)", "(null)", "(null)",
    "(none)", "0", "100-120", "3-7", "150-180", "5-15", "15-20", "on", "on", "0xca6c"])

HOME = """default via 192.168.31.1 dev wlan0 proto dhcp src 192.168.31.50 metric 600
203.0.113.7 via 192.168.31.1 dev wlan0
"""
HOTSPOT_STALE_PIN = """default via 172.20.10.1 dev wlan0 proto dhcp src 172.20.10.2 metric 600
203.0.113.7 via 192.168.31.1 dev wlan0
"""
OFFLINE = "203.0.113.7 via 192.168.31.1 dev wlan0 \n"
DOCK_AND_SPLIT_TUNNEL = """default via 10.0.0.1 dev enp4s0f3u1u4 proto dhcp src 10.0.0.23 metric 100
default via 172.20.10.1 dev wlan0 proto dhcp src 172.20.10.2 metric 600
128.0.0.0/1 dev vd-work scope link
203.0.113.0/24 dev vd-work scope link
203.0.113.7 via 192.168.31.1 dev wlan0
"""
LAN_ENDPOINT = """default via 192.168.31.1 dev wlan0 proto dhcp src 192.168.31.50 metric 600
192.168.31.0/24 dev wlan0 proto kernel scope link src 192.168.31.50 metric 600
"""
MULTIPATH = """default proto static metric 600
	nexthop via 172.20.10.1 dev wlan0 weight 1
	nexthop via 10.0.0.1 dev eth0 weight 1
203.0.113.7 via 192.168.31.1 dev wlan0
"""
SKIPPED_KINDS = """unreachable default metric 4278198272
default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.23 metric 100 linkdown
default via 172.20.10.1 dev wlan0 proto dhcp src 172.20.10.2 metric 600
"""
IPV6 = """2001:db8::7 via fe80::1 dev wlan0 metric 1024 pref medium
default via fe80::a0de:48ff:fe00:1122 dev wlan0 proto ra metric 600 pref medium
"""


def test_parse_routes_host_default_and_subnet():
    routes = parse_routes(LAN_ENDPOINT + OFFLINE)
    assert routes == [
        Route(prefixlen=0, gateway="192.168.31.1", dev="wlan0", metric=600),
        Route(prefixlen=24, gateway=None, dev="wlan0", metric=600),
        Route(prefixlen=32, gateway="192.168.31.1", dev="wlan0", metric=0),
    ]


def test_parse_routes_skips_unusable_and_nexthop_lines():
    assert parse_routes(SKIPPED_KINDS) == [Route(0, "172.20.10.1", "wlan0", 600)]
    assert parse_routes(MULTIPATH) == [Route(0, None, None, 600), Route(32, "192.168.31.1", "wlan0", 0)]
    assert parse_routes("") == []


def test_parse_routes_ipv6():
    routes = parse_routes(IPV6)
    assert find_pin(routes, 128) == Route(128, "fe80::1", "wlan0", 1024)
    assert underlay_route(routes, 128, []) == Route(0, "fe80::a0de:48ff:fe00:1122", "wlan0", 600)


def test_underlay_route_ignores_pin_and_tunnel_routes():
    routes = parse_routes(HOTSPOT_STALE_PIN)
    assert find_pin(routes, 32) == Route(32, "192.168.31.1", "wlan0", 0)
    assert underlay_route(routes, 32, ["vd-home"]) == Route(0, "172.20.10.1", "wlan0", 600)

    # The split-tunnel routes cover the endpoint more specifically but belong to the tunnel.
    routes = parse_routes(DOCK_AND_SPLIT_TUNNEL)
    assert underlay_route(routes, 32, ["vd-work"]) == Route(0, "10.0.0.1", "enp4s0f3u1u4", 100)

    routes = parse_routes(LAN_ENDPOINT)
    assert underlay_route(routes, 32, []) == Route(24, None, "wlan0", 600)


def test_underlay_route_offline_and_multipath():
    assert underlay_route(parse_routes(OFFLINE), 32, []) is None
    assert underlay_route(parse_routes(MULTIPATH), 32, []) is None


def test_decide_repin():
    pin = Route(32, "192.168.31.1", "wlan0")
    home = Route(0, "192.168.31.1", "wlan0", 600)
    hotspot = Route(0, "172.20.10.1", "wlan0", 600)
    dock = Route(0, "192.168.31.1", "eth0", 100)
    on_link = Route(24, None, "wlan0", 600)

    assert decide_repin(pin, hotspot) == hotspot
    assert decide_repin(pin, dock) == dock
    assert decide_repin(pin, home) is None
    assert decide_repin(pin, None) is None
    assert decide_repin(pin, on_link) is None
    assert decide_repin(None, hotspot) == hotspot


def test_parse_dump():
    dump = "\n".join([
        DUMP_INTERFACE,
        f"{KEY}\t(none)\t{ENDPOINT}:46907\t0.0.0.0/0,::/0\t1727712000\t100\t200\t25-35",
        f"{KEY2}\t(none)\t(none)\t(none)\t0\t0\t0\toff",
    ])
    endpoints, handshakes, keepalives = parse_dump(dump)
    assert endpoints == {KEY: f"{ENDPOINT}:46907", KEY2: "(none)"}
    assert handshakes == {KEY: "1727712000", KEY2: "0"}
    assert keepalives == {KEY: "25-35", KEY2: "off"}
    assert parse_dump(DUMP_INTERFACE) == ({}, {}, {})
    assert parse_dump("") == ({}, {}, {})
    assert parse_endpoint_ip(endpoints[KEY]) == ENDPOINT
    assert parse_endpoint_ip("(none)") is None
    assert parse_endpoint_ip("[2001:db8::7]:51820") == "2001:db8::7"
    assert parse_endpoint_ip("vpn.example.com:51820") is None


def test_parse_state_file():
    assert parse_state_file("-4 203.0.113.7/32\n-6 2001:db8:0::7/128\n\ngarbage\n-4 not-an-ip/32\n") == {
        ENDPOINT, "2001:db8::7"}
    assert parse_state_file("") == set()


def test_handshake_age():
    endpoints = {KEY: ENDPOINT, KEY2: "198.51.100.1"}
    now = 10_000.0
    assert handshake_age(endpoints, {KEY: "9400", KEY2: "9990"}, {KEY: "25", KEY2: "25"}, now) == 600
    assert handshake_age(endpoints, {KEY: "9400", KEY2: "9990"}, {KEY: "off", KEY2: "25"}, now) == 10
    assert handshake_age(endpoints, {KEY: "0", KEY2: "0"}, {KEY: "25", KEY2: "25"}, now) is None
    assert handshake_age(endpoints, {KEY: "9400"}, {}, now) is None


def test_should_restart_grace_and_backoff():
    st = IfaceState()
    assert not st.should_restart(600, True, False, 1000)   # stale seen for the first time
    assert not st.should_restart(630, True, False, 1030)   # still within grace
    assert st.should_restart(660, True, False, 1060)
    st.last_restart, st.stale_since = 1060, None
    assert not st.should_restart(700, True, False, 1100)
    assert not st.should_restart(900, True, False, 1300)   # grace passed, backoff not
    assert st.should_restart(1000, True, False, 1400)


def test_should_restart_waits_after_repin_and_offline():
    st = IfaceState(stale_since=0)
    assert not st.should_restart(600, True, True, 1000)
    assert not st.should_restart(630, True, False, 1030)
    assert st.should_restart(700, True, False, 1070)

    st = IfaceState(stale_since=0)
    assert not st.should_restart(600, False, False, 1000)  # offline: grace restarts when back online
    assert not st.should_restart(600, True, False, 1015)
    assert st.should_restart(700, True, False, 1080)

    st = IfaceState(stale_since=0)
    assert not st.should_restart(60, True, False, 1000)    # fresh handshake
    assert not st.should_restart(None, True, False, 1000)  # never handshaked or no keepalive
    assert st.stale_since is None


class FakeService:
    """ServiceManager stand-in: canned `awg show` / `ip route` output, no real commands."""

    def __init__(self, ifaces, routes, handshake_ago, keepalive="25", replace_rc=0, start_ok=True):
        self.binary_manager = types.SimpleNamespace(get_binary_path=lambda name: "/bin/awg")
        self.lock = threading.RLock()
        self.ifaces = list(ifaces)
        self.routes = routes
        self.handshake_ago = handshake_ago
        self.keepalive = keepalive
        self.replace_rc = replace_rc
        self.start_ok = start_ok
        self.now = 0.0
        self.commands = []
        self.events = []

    def list_interfaces(self):
        return list(self.ifaces)

    def run_command(self, cmd, timeout=10):
        self.commands.append(cmd)
        line = " ".join(cmd)
        if line == f"/bin/awg show {cmd[2]} dump":
            handshake = int(self.now - self.handshake_ago)
            peer = f"{KEY}\t(none)\t{ENDPOINT}:46907\t0.0.0.0/0\t{handshake}\t100\t200\t{self.keepalive}"
            return 0, f"{DUMP_INTERFACE}\n{peer}", ""
        if line == f"ip -4 route show table main match {ENDPOINT}/32":
            return 0, self.routes, ""
        if line.startswith(f"ip -4 route replace {ENDPOINT}/32 via "):
            if self.replace_rc:
                return self.replace_rc, "", "RTNETLINK answers: Network is unreachable"
            pin = f"{ENDPOINT} via {cmd[6]} dev {cmd[8]} "
            self.routes = "\n".join(pin if r.startswith(f"{ENDPOINT} ") else r for r in self.routes.splitlines())
            return 0, "", ""
        raise AssertionError(f"unexpected command: {line}")

    def stop_interface(self, iface):
        self.events.append(("stop", iface))
        if iface in self.ifaces:
            self.ifaces.remove(iface)
        return {"success": True, "error": None}

    def start_interface(self, iface):
        self.events.append(("start", iface))
        if self.start_ok and iface not in self.ifaces:
            self.ifaces.append(iface)
        return {"success": self.start_ok, "error": None if self.start_ok else "awg-quick up failed (rc=1)"}


class Watch:
    """NetworkWatch over a FakeService with a temporary awg-quick state dir."""

    def __init__(self, service, pinned=(ENDPOINT,)):
        self.dir = tempfile.mkdtemp(prefix="vpn-deck-watch-")
        if pinned:
            with open(os.path.join(self.dir, "vd-home.endpoint-routes"), "w") as f:
                f.writelines(f"-4 {ip}/32\n" for ip in pinned)
        self.service = service
        self.errors = []
        self.watch = NetworkWatch(service, lambda *args: self.errors.append(args), state_dir=self.dir)

    def tick(self, now):
        self.service.now = now
        self.watch.tick(now=now)

    def replaces(self):
        return [" ".join(c) for c in self.service.commands if "replace" in c]

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def test_tick_repins_after_gateway_change():
    w = Watch(FakeService(["vd-home"], HOTSPOT_STALE_PIN, handshake_ago=30))
    try:
        w.tick(1000)
        assert w.replaces() == [f"ip -4 route replace {ENDPOINT}/32 via 172.20.10.1 dev wlan0"]
        w.tick(1015)
        assert len(w.replaces()) == 1, "pin is up to date now"
        assert w.service.events == [] and w.errors == []
    finally:
        w.close()


def test_tick_leaves_good_or_unknown_routes_alone():
    for routes in (HOME, OFFLINE, LAN_ENDPOINT, MULTIPATH):
        w = Watch(FakeService(["vd-home"], routes, handshake_ago=30))
        try:
            w.tick(1000)
            assert w.replaces() == [], routes
        finally:
            w.close()


def test_tick_does_not_touch_pins_awg_quick_did_not_record():
    w = Watch(FakeService(["vd-home"], HOTSPOT_STALE_PIN, handshake_ago=30), pinned=())
    try:
        w.tick(1000)
        assert w.replaces() == []
    finally:
        w.close()


def test_tick_ignores_down_and_foreign_interfaces():
    for ifaces in ([], ["awg0"], ["wg0", "awg-home"]):
        w = Watch(FakeService(ifaces, HOTSPOT_STALE_PIN, handshake_ago=3600))
        try:
            for now in range(1000, 2000, 15):
                w.tick(now)
            assert w.service.commands == [] and w.service.events == [], ifaces
        finally:
            w.close()


def test_tick_restarts_stuck_tunnel_once_per_backoff():
    w = Watch(FakeService(["vd-home"], HOME, handshake_ago=600))
    try:
        for now in range(1000, 1060, 15):
            w.tick(now)
        assert w.service.events == []
        w.tick(1060)
        assert w.service.events == [("stop", "vd-home"), ("start", "vd-home")]
        for now in range(1075, 1360, 15):
            w.tick(now)
        assert len(w.service.events) == 2, "backoff holds the next restart"
        w.tick(1360)
        assert len(w.service.events) == 4
        assert w.errors == []
    finally:
        w.close()


def test_tick_never_restarts_without_keepalive_or_when_offline():
    for service in (FakeService(["vd-home"], HOME, handshake_ago=600, keepalive="off"),
                    FakeService(["vd-home"], OFFLINE, handshake_ago=600)):
        w = Watch(service)
        try:
            for now in range(1000, 3000, 15):
                w.tick(now)
            assert w.service.events == []
        finally:
            w.close()


def test_tick_repin_postpones_restart():
    w = Watch(FakeService(["vd-home"], HOTSPOT_STALE_PIN, handshake_ago=900))
    try:
        w.tick(1000)
        assert len(w.replaces()) == 1 and w.service.events == []
        w.tick(1045)
        assert w.service.events == []
        w.tick(1060)
        assert w.service.events == [("stop", "vd-home"), ("start", "vd-home")]
    finally:
        w.close()


def test_failures_go_to_error_history_once():
    w = Watch(FakeService(["vd-home"], HOTSPOT_STALE_PIN, handshake_ago=30, replace_rc=2))
    try:
        for now in range(1000, 1100, 15):
            w.tick(now)
        assert len(w.replaces()) == 7
        assert [(e[0], e[3]) for e in w.errors] == [("network_watch.repin", {"interface": "vd-home"})]
    finally:
        w.close()

    w = Watch(FakeService(["vd-home"], HOME, handshake_ago=600, start_ok=False))
    try:
        w.tick(1000)
        w.tick(1060)
        assert w.service.events == [("stop", "vd-home"), ("start", "vd-home")]
        assert [e[0] for e in w.errors] == ["network_watch.restart"]
    finally:
        w.close()


def test_tunnel_that_went_down_starts_from_scratch():
    w = Watch(FakeService(["vd-home"], HOTSPOT_STALE_PIN, handshake_ago=30, replace_rc=2))
    try:
        w.tick(1000)
        w.tick(1015)
        assert len(w.errors) == 1
        w.service.ifaces = []
        w.tick(1030)
        assert w.watch._states == {} and w.watch._reported == {}
        w.service.ifaces = ["vd-home"]
        w.tick(1045)
        assert len(w.errors) == 2, "same failure after a manual re-up is reported again"
    finally:
        w.close()


def test_failed_up_is_retried_until_the_user_steps_in():
    w = Watch(FakeService(["vd-home"], HOME, handshake_ago=600, start_ok=False))
    try:
        w.tick(1000)
        w.tick(1060)
        assert w.service.events == [("stop", "vd-home"), ("start", "vd-home")]
        assert w.service.ifaces == []
        for now in range(1075, 1120, 15):
            w.tick(now)
        assert len(w.service.events) == 2, "retries wait RETRY_UP_SEC"
        w.tick(1120)
        assert w.service.events[-1] == ("start", "vd-home") and len(w.service.events) == 3
        assert len(w.errors) == 1, "the same failure is reported once"
        w.service.start_ok = True
        w.tick(1180)
        assert w.service.ifaces == ["vd-home"] and w.watch._pending_up == {}
        assert len(w.service.events) == 4
    finally:
        w.close()

    w = Watch(FakeService(["vd-home"], HOME, handshake_ago=600, start_ok=False))
    try:
        w.tick(1000)
        w.tick(1060)
        w.watch.forget("vd-home")
        for now in range(1075, 1500, 15):
            w.tick(now)
        assert w.service.events == [("stop", "vd-home"), ("start", "vd-home")], "the user's choice wins"
    finally:
        w.close()


def test_start_is_idempotent_and_stop_cancels():
    async def scenario():
        service = FakeService([], HOME, handshake_ago=30)
        watch = NetworkWatch(service, state_dir="/nonexistent")
        watch.start()
        task = watch._task
        watch.start()
        assert watch._task is task
        await asyncio.sleep(0.05)
        assert not task.done()
        await watch.stop()
        assert task.cancelled() and watch._task is None
        await watch.stop()

    interval = nw.CHECK_INTERVAL_SEC
    nw.CHECK_INTERVAL_SEC = 0.01
    try:
        asyncio.run(scenario())
    finally:
        nw.CHECK_INTERVAL_SEC = interval


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"✓ {t.__name__}")
    print(f"✅ network watch tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
