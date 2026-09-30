#!/usr/bin/env python3
"""
Unit tests for the connection status under an active tunnel and for the persistent settings
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_modules"))
_here = os.path.dirname(os.path.abspath(__file__))
sys.modules.setdefault("decky", types.SimpleNamespace(
    logger=types.SimpleNamespace(info=print, debug=print, warning=print, error=print),
    DECKY_PLUGIN_DIR=_here, DECKY_PLUGIN_LOG_DIR=os.path.join(_here, "logs"),
    DECKY_PLUGIN_SETTINGS_DIR=os.path.join(_here, "settings")))

from vpn_deck import status as st
from vpn_deck.settings import Settings
from vpn_deck.status import ConnectionStatus, parse_ipv4_address, parse_trace

KEY = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
TRACE = """fl=123f45
h=1.1.1.1
ip=151.243.247.251
ts=1790000000.123
visit_scheme=https
uag=curl/8.9.1
colo=HEL
http=http/2
loc=FI
tls=TLSv1.3
"""


def test_parse_trace():
    assert parse_trace(TRACE) == {"ip": "151.243.247.251", "country": "FI"}
    assert parse_trace("ip=2001:db8::7\n") == {"ip": "2001:db8::7", "country": ""}
    assert parse_trace("") is None and parse_trace("<html>captive portal</html>") is None


def test_parse_ipv4_address():
    out = "5: vd-fi    inet 10.8.1.3/32 scope global vd-fi\\       valid_lft forever preferred_lft forever"
    assert parse_ipv4_address(out) == "10.8.1.3"
    assert parse_ipv4_address("") is None


class FakeService:
    def __init__(self, handshake):
        self.binary_manager = types.SimpleNamespace(get_binary_path=lambda name: "/bin/awg")
        self.handshake = handshake
        self.commands = []

    def run_command(self, cmd, timeout=10):
        self.commands.append(cmd)
        if cmd[:3] == ["ip", "-4", "-o"]:
            return 0, f"5: {cmd[-1]}    inet 10.8.1.3/32 scope global {cmd[-1]}", ""
        if cmd[-1] == "dump":
            return 0, f"(none)\tPUB\t0\toff\n{KEY}\t(none)\t151.243.247.251:46907\t0.0.0.0/0\t{self.handshake}\t1\t2\t25", ""
        raise AssertionError(cmd)


class Env:
    def __init__(self, fetch=None):
        self.dir = tempfile.mkdtemp(prefix="vpn-deck-status-")
        for iface, rx, tx in (("vd-fi", 1000, 200), ("vd-vless", 5000, 700)):
            stats = os.path.join(self.dir, iface, "statistics")
            os.makedirs(stats)
            for name, value in (("rx_bytes", rx), ("tx_bytes", tx)):
                with open(os.path.join(stats, name), "w") as f:
                    f.write(f"{value}\n")
        self.fetches = 0
        self.release = threading.Event()
        self.fetch_result = {"ip": "151.243.247.251", "country": "FI"}

        def default_fetch():
            self.fetches += 1
            self.release.wait(2)
            return self.fetch_result

        self.service = FakeService(handshake=int(time.time()) - 20)
        self.status = ConnectionStatus(self.service, net_dir=self.dir, fetch_exit=fetch or default_fetch)

    def wait_idle(self):
        for _ in range(100):
            if not self.status._pending:
                return
            time.sleep(0.01)
        raise AssertionError("exit check did not finish")

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def test_snapshot_awg_and_singbox():
    env = Env()
    try:
        now = time.time()
        snap = env.status.snapshot([("fi", "vd-fi", "awg"), ("vless", "vd-vless", "sing-box")], now=now)
        fi, vless = snap
        assert fi["address"] == "10.8.1.3" and 19 <= fi["handshake_age"] <= 21
        assert (fi["rx_bytes"], fi["tx_bytes"]) == (1000, 200) and fi["sampled_at"] == now
        assert vless["address"] is None and vless["handshake_age"] is None and vless["rx_bytes"] == 5000
        # The first poll starts the exit check in the background and does not wait for it.
        assert fi["exit_ip"] is None and vless["exit_ip"] is None
        assert not any(c[0] == "/bin/awg" and c[2] == "vd-vless" for c in env.service.commands)
        env.release.set()
        env.wait_idle()
        snap = env.status.snapshot([("fi", "vd-fi", "awg")], now=time.time())
        assert (snap[0]["exit_ip"], snap[0]["exit_country"]) == ("151.243.247.251", "FI")
        assert env.fetches == 2, "one check per tunnel, the next only after EXIT_REFRESH_SEC"
    finally:
        env.close()


def test_exit_is_rechecked_when_stale_or_after_reconnect():
    env = Env()
    env.release.set()
    try:
        env.status.snapshot([("fi", "vd-fi", "awg")], now=1000)
        env.wait_idle()
        env.status.snapshot([("fi", "vd-fi", "awg")], now=1000 + st.EXIT_REFRESH_SEC - 1)
        env.wait_idle()
        assert env.fetches == 1
        env.status.snapshot([("fi", "vd-fi", "awg")], now=1000 + st.EXIT_REFRESH_SEC)
        env.wait_idle()
        assert env.fetches == 2
        env.status.snapshot([], now=2000)
        assert env.status._exits == {}
        env.status.snapshot([("fi", "vd-fi", "awg")], now=2001)
        env.wait_idle()
        assert env.fetches == 3
    finally:
        env.close()


def test_failed_exit_check_retries_soon_and_keeps_the_last_answer():
    env = Env()
    env.release.set()
    try:
        env.status.snapshot([("fi", "vd-fi", "awg")], now=time.time())
        env.wait_idle()
        env.fetch_result = None
        entry = env.status._exits["vd-fi"]
        env.status._exits["vd-fi"] = dict(entry, checked_at=entry["checked_at"] - st.EXIT_REFRESH_SEC)
        env.status.snapshot([("fi", "vd-fi", "awg")], now=time.time())
        env.wait_idle()
        entry = env.status._exits["vd-fi"]
        assert entry["ip"] == "151.243.247.251"
        assert time.time() - entry["checked_at"] >= st.EXIT_REFRESH_SEC - st.EXIT_RETRY_SEC - 1
    finally:
        env.close()


def test_answer_for_a_tunnel_that_went_down_is_dropped():
    env = Env()
    try:
        env.status.snapshot([("fi", "vd-fi", "awg")], now=time.time())
        env.status.snapshot([], now=time.time())
        env.release.set()
        env.wait_idle()
        assert env.status._exits == {}
    finally:
        env.close()


def test_settings_defaults_persist_and_survive_garbage():
    d = tempfile.mkdtemp(prefix="vpn-deck-settings-")
    try:
        path = os.path.join(d, "sub", "settings.json")
        s = Settings(path)
        assert s.get("restore_on_boot") is True and s.get("last_active") is None
        s.set("last_active", "fi-vless")
        s.set("restore_on_boot", False)
        assert Settings(path).data == {"restore_on_boot": False, "last_active": "fi-vless"}
        with open(path, "w") as f:
            json.dump({"last_active": "fi", "unknown": 1}, f)
        assert Settings(path).data == {"restore_on_boot": True, "last_active": "fi"}
        with open(path, "w") as f:
            f.write("{broken")
        assert Settings(path).get("last_active") is None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"✓ {t.__name__}")
    print(f"\n✅ status tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
