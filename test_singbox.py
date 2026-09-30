#!/usr/bin/env python3
"""
Unit tests for sing-box support: vless:// links, sing-box JSON configs and the tunnel process
"""

import json
import os
import shutil
import signal
import stat
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_modules"))
_here = os.path.dirname(os.path.abspath(__file__))
sys.modules.setdefault("decky", types.SimpleNamespace(
    logger=types.SimpleNamespace(info=print, debug=print, warning=print, error=print),
    DECKY_PLUGIN_DIR=_here, DECKY_PLUGIN_LOG_DIR=os.path.join(_here, "logs")))

from vpn_deck import singbox_manager as sbm
from vpn_deck.singbox import (
    SingBoxError, is_vless_uri, looks_like_json, protocol_label, singbox_config, tun_config, vless_link,
    vless_outbound,
)
from vpn_deck.singbox_manager import SingBoxManager, resolve_server


UUID = "3f1c2a9e-8b7d-4c6e-9a1b-2d3e4f5a6b7c"
# The shape xray-user prints for our servers.
WS_TLS = (f"vless://{UUID}@cdn4.example.org:443?encryption=none&security=tls&sni=cdn4.example.org"
          f"&fp=chrome&type=ws&host=cdn4.example.org&path=%2Fdeck-ws#steamdeck")
REALITY = (f"vless://{UUID}@203.0.113.7:8443?encryption=none&flow=xtls-rprx-vision&security=reality"
           f"&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123abcd&type=tcp")


def expect_error(fn, *args, contains=""):
    try:
        fn(*args)
    except SingBoxError as e:
        assert contains in str(e), f"{contains!r} not in {e!r}"
        return
    raise AssertionError(f"no SingBoxError for {args!r}")


def test_detection():
    assert is_vless_uri(WS_TLS)
    assert is_vless_uri("﻿  VLESS://x@y:1\r\n")
    assert not is_vless_uri("vpn://abc") and not is_vless_uri("[Interface]")
    assert looks_like_json('﻿\n  {"outbounds": []}')
    assert not looks_like_json(WS_TLS)


def test_ws_tls_link_from_xray_user():
    assert vless_outbound(WS_TLS + "\n") == {
        "type": "vless", "tag": "proxy", "server": "cdn4.example.org", "server_port": 443, "uuid": UUID,
        "tls": {"enabled": True, "server_name": "cdn4.example.org",
                "utls": {"enabled": True, "fingerprint": "chrome"}},
        "transport": {"type": "ws", "path": "/deck-ws", "headers": {"Host": "cdn4.example.org"}},
    }


def test_ws_early_data_and_defaults():
    out = vless_outbound(f"vless://{UUID}@h.example:8080?type=ws&path=%2Fws%3Fed%3D2048")
    assert "tls" not in out and out["server_port"] == 8080
    assert out["transport"] == {"type": "ws", "path": "/ws", "max_early_data": 2048,
                                "early_data_header_name": "Sec-WebSocket-Protocol"}
    out = vless_outbound(f"vless://{UUID}@h.example?type=ws&path=%2Fws%3Ftoken%3Dabc%26ed%3D2048")
    assert out["transport"]["path"] == "/ws?token=abc" and out["transport"]["max_early_data"] == 2048
    out = vless_outbound(f"vless://{UUID}@h.example")
    assert out["server_port"] == 443 and "transport" not in out and "tls" not in out


def test_reality_vision():
    out = vless_outbound(REALITY)
    assert out["flow"] == "xtls-rprx-vision" and out["server"] == "203.0.113.7" and out["server_port"] == 8443
    assert out["tls"] == {
        "enabled": True, "server_name": "www.example.com",
        "reality": {"enabled": True, "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "short_id": "0123abcd"},
        "utls": {"enabled": True, "fingerprint": "chrome"},
    }
    assert "transport" not in out


def test_other_transports_and_tls_options():
    out = vless_outbound(f"vless://{UUID}@h.example:443?security=tls&type=grpc&serviceName=svc&alpn=h2,http%2F1.1&allowInsecure=1")
    assert out["transport"] == {"type": "grpc", "service_name": "svc"}
    assert out["tls"]["alpn"] == ["h2", "http/1.1"] and out["tls"]["insecure"] is True and "utls" not in out["tls"]
    out = vless_outbound(f"vless://{UUID}@h.example:443?security=tls&type=httpupgrade&host=cdn.example&path=%2Fup")
    assert out["transport"] == {"type": "httpupgrade", "path": "/up", "host": "cdn.example"}
    assert out["tls"]["server_name"] == "cdn.example"
    out = vless_outbound(f"vless://{UUID}@[2001:db8::7]:443?security=tls&type=h2&host=a.example,b.example")
    assert out["server"] == "2001:db8::7"
    assert out["transport"] == {"type": "http", "path": "/", "host": ["a.example", "b.example"]}


def test_link_errors():
    expect_error(vless_outbound, "vless://@h.example:443", contains="UUID")
    expect_error(vless_outbound, f"vless://{UUID}@h.example:99999", contains="разобрать")
    expect_error(vless_outbound, f"vless://{UUID}@h.example?type=xhttp", contains="xhttp")
    expect_error(vless_outbound, f"vless://{UUID}@h.example?encryption=mlkem768x25519plus", contains="шифрование")
    expect_error(vless_outbound, f"vless://{UUID}@h.example?headerType=http", contains="headerType")
    expect_error(vless_outbound, f"vless://{UUID}@h.example?security=reality", contains="pbk")
    expect_error(vless_outbound, f"vless://{UUID}@h.example?security=xtls", contains="security=xtls")
    expect_error(vless_outbound, WS_TLS + "\n" + REALITY, contains="одна ссылка")
    expect_error(vless_outbound, "", contains="одна ссылка")
    expect_error(vless_outbound, f"vless://{UUID}@h.example?path=/a b", contains="пробелы")
    expect_error(vless_outbound, "trojan://x@h.example:443", contains="не ссылка")


def test_link_with_a_spaced_remark_is_stored_as_is():
    link = WS_TLS.replace("#steamdeck", "#\U0001f1eb\U0001f1ee Finland 1")
    assert vless_link("\ufeff\n" + link + "\r\n\n") == link
    assert vless_outbound(link) == vless_outbound(WS_TLS)


def test_tun_config():
    config = singbox_config(WS_TLS, "vd-deck")
    assert config == tun_config(vless_outbound(WS_TLS), "vd-deck")
    tun = config["inbounds"][0]
    assert tun["type"] == "tun" and tun["interface_name"] == "vd-deck" and tun["auto_route"] and tun["strict_route"]
    # DNS to a LAN resolver must reach hijack-dns; private addresses still go direct by the route rule.
    assert "route_exclude_address" not in tun
    assert {"ip_is_private": True, "outbound": "direct"} in config["route"]["rules"]
    assert [s["tag"] for s in config["dns"]["servers"]] == ["remote", "local"]
    assert "domain_resolver" not in config["outbounds"][0]
    assert [o["tag"] for o in config["outbounds"]] == ["proxy", "direct"]
    assert config["route"]["final"] == "proxy" and config["dns"]["servers"][0]["detour"] == "proxy"
    assert {"protocol": "dns", "action": "hijack-dns"} in config["route"]["rules"]


def test_tun_config_pins_the_server_address():
    config = tun_config(vless_outbound(WS_TLS), "vd-deck", "151.243.247.251")
    assert config["dns"]["servers"][-1] == {
        "type": "hosts", "tag": "server", "predefined": {"cdn4.example.org": ["151.243.247.251"]}}
    proxy = config["outbounds"][0]
    assert proxy["server"] == "cdn4.example.org" and proxy["domain_resolver"] == "server"
    assert proxy["tls"]["server_name"] == "cdn4.example.org"
    reality = tun_config(vless_outbound(REALITY), "vd-r", "203.0.113.7")
    assert "domain_resolver" not in reality["outbounds"][0] and len(reality["dns"]["servers"]) == 2


def test_resolve_server():
    assert resolve_server("203.0.113.7", 443) == "203.0.113.7"
    assert resolve_server("2001:db8::7", 443) == "2001:db8::7"
    assert resolve_server("localhost", 443) == "127.0.0.1"
    try:
        resolve_server("no-such-host.invalid", 443)
    except SingBoxError as e:
        assert "no-such-host.invalid" in str(e)
    else:
        raise AssertionError("no error for an unknown host")


def test_user_json_config():
    user = {"log": {"level": "info"},
            "inbounds": [{"type": "mixed", "listen_port": 2080}, {"type": "tun", "interface_name": "tun0"}],
            "outbounds": [{"type": "selector", "tag": "select"}, {"type": "trojan", "tag": "t"}, {"type": "direct"}]}
    config = singbox_config("﻿" + json.dumps(user), "vd-trojan")
    assert config["inbounds"][1]["interface_name"] == "vd-trojan" and config["inbounds"][0] == user["inbounds"][0]
    assert config["log"] == {"level": "info"}
    expect_error(singbox_config, '{"inbounds": [{"type": "socks"}]}', "vd-x", contains="tun")
    expect_error(singbox_config, '{"inbounds": [{"type": "tun"}, {"type": "tun"}]}', "vd-x", contains="ровно один")
    expect_error(singbox_config, '{"outbounds": [', "vd-x", contains="не JSON")
    expect_error(singbox_config, "[Interface]", "vd-x", contains="не JSON sing-box")
    xray = {"inbounds": [{"protocol": "socks", "port": 10808}], "outbounds": [{"protocol": "vless"}]}
    expect_error(singbox_config, json.dumps(xray), "vd-x", contains="xray")


def test_protocol_label():
    assert protocol_label(singbox_config(WS_TLS, "vd-x")) == "VLESS"
    assert protocol_label({"outbounds": [{"type": "selector"}, {"type": "hysteria2"}]}) == "HYSTERIA2"
    assert protocol_label({"outbounds": [{"type": "direct"}]}) is None
    assert protocol_label({"outbounds": "nope"}) is None and protocol_label([]) is None


# A stand-in for the sing-box binary: `check` validates JSON, `run` creates the "interface" and waits for SIGTERM.
FAKE_SING_BOX = r'''#!/usr/bin/env python3
import json, os, signal, sys, time
command, config_path = sys.argv[1], sys.argv[3]
text = sys.stdin.read() if config_path == "stdin" else open(config_path).read()
config = json.loads(text)
if command == "check":
    if config.get("fail_check"):
        print("FATAL[0000] decode config at stdin: boom", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
if config.get("fail_run"):
    print("FATAL[0000] start service: configure tun interface: operation not permitted", flush=True)
    sys.exit(1)
link = os.path.join(os.environ["FAKE_NET_DIR"], config["inbounds"][0]["interface_name"])
def bye(*_):
    if os.path.exists(link):
        os.unlink(link)
    sys.exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN if config.get("ignore_term") else bye)
if not config.get("no_tun"):
    open(link, "w").close()
while True:
    time.sleep(0.05)
'''


class FakeSingBoxManager(SingBoxManager):
    """/proc does not exist off Linux: treat any live process of ours as sing-box."""

    def _process_argv(self, pid):
        try:
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                return None
        except ChildProcessError:
            pass
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return None
        return [b"/plugin/bin/sing-box", b"run"]


class Env:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="vpn-deck-sb-")
        self.net = os.path.join(self.dir, "net")
        os.makedirs(self.net)
        binary = os.path.join(self.dir, "sing-box")
        with open(binary, "w") as f:
            f.write(FAKE_SING_BOX)
        os.chmod(binary, os.stat(binary).st_mode | stat.S_IXUSR)
        self.saved_env = os.environ.get("FAKE_NET_DIR")
        os.environ["FAKE_NET_DIR"] = self.net
        self.resolved = []
        bm = types.SimpleNamespace(get_binary_path=lambda name: binary if name == "sing-box" else None)
        self.manager = self.new_manager(bm)

    def resolve(self, host, port):
        self.resolved.append((host, port))
        return "198.51.100.9"

    def new_manager(self, bm=None):
        return FakeSingBoxManager(bm or self.manager.binary_manager, run_dir=os.path.join(self.dir, "run"),
                                  log_dir=self.dir, net_dir=self.net, resolve=self.resolve)

    def config(self, name, **flags):
        path = os.path.join(self.dir, f"{name}.json")
        with open(path, "w") as f:
            json.dump({"inbounds": [{"type": "tun", "interface_name": f"vd-{name}"}], **flags}, f)
        return path

    def close(self):
        for iface in self.manager.running():
            self.manager.stop(iface)
        shutil.rmtree(self.dir, ignore_errors=True)
        if self.saved_env is None:
            os.environ.pop("FAKE_NET_DIR", None)
        else:
            os.environ["FAKE_NET_DIR"] = self.saved_env


def test_manager_check():
    env = Env()
    try:
        assert env.manager.check('{"outbounds": []}') is None
        assert "boom" in env.manager.check('{"fail_check": true}')
        assert SingBoxManager(types.SimpleNamespace(get_binary_path=lambda n: None)).check("{}") == "sing-box binary not found"
    finally:
        env.close()


def test_manager_start_stop():
    env = Env()
    try:
        m = env.manager
        r = m.start("vd-deck", env.config("deck"))
        assert r["success"] and r["error"] is None, r
        assert m.running() == ["vd-deck"] and os.path.exists(os.path.join(env.net, "vd-deck"))
        assert m.start("vd-deck", env.config("deck"))["success"], "already running is fine"
        pid = m.pid("vd-deck")

        # A fresh manager, like after a plugin reload, finds the tunnel by its PID file and stops it.
        m2 = env.new_manager()
        assert m2.running() == ["vd-deck"] and m2.pid("vd-deck") == pid
        assert m2.stop("vd-deck")["success"]
        assert m.running() == [] and not os.path.exists(os.path.join(env.net, "vd-deck"))
        assert not m.stop("vd-deck")["success"]
    finally:
        env.close()


def test_manager_builds_the_config_from_a_stored_link():
    env = Env()
    try:
        path = os.path.join(env.dir, "fi.vless")
        with open(path, "w") as f:
            f.write(WS_TLS + "\n")
        r = env.manager.start("vd-fi", path)
        assert r["success"], r
        assert env.resolved == [("cdn4.example.org", 443)]
        runtime = os.path.join(env.dir, "run", "vd-fi.json")
        with open(runtime) as f:
            assert json.load(f) == tun_config(vless_outbound(WS_TLS), "vd-fi", "198.51.100.9")
        assert oct(os.stat(runtime).st_mode & 0o777) == "0o600"
        assert env.manager.stop("vd-fi")["success"] and not os.path.exists(runtime)

        with open(path, "w") as f:
            f.write("vless://broken")
        r = env.manager.start("vd-fi", path)
        assert not r["success"] and "Не удалось собрать конфиг" in r["error"], r
    finally:
        env.close()


def test_manager_start_failures():
    env = Env()
    try:
        m = env.manager
        r = m.start("vd-bad", env.config("bad", fail_check=True))
        assert not r["success"] and "sing-box не принял конфиг" in r["error"] and "boom" in r["error"], r
        r = m.start("vd-perm", env.config("perm", fail_run=True))
        assert not r["success"] and "operation not permitted" in r["error"], r
        assert m.running() == [] and not os.listdir(os.path.join(env.dir, "run"))

        timeout = sbm.START_TIMEOUT_SEC
        sbm.START_TIMEOUT_SEC = 0.5
        try:
            r = m.start("vd-slow", env.config("slow", no_tun=True))
        finally:
            sbm.START_TIMEOUT_SEC = timeout
        assert not r["success"] and "не поднял vd-slow" in r["error"], r
        assert m.running() == []
    finally:
        env.close()


def test_manager_kills_sing_box_that_ignores_sigterm():
    env = Env()
    stop_timeout = sbm.STOP_TIMEOUT_SEC
    sbm.STOP_TIMEOUT_SEC = 0.3
    try:
        m = env.manager
        assert m.start("vd-stuck", env.config("stuck", ignore_term=True))["success"]
        child = m._children["vd-stuck"]
        assert m.stop("vd-stuck")["success"]
        assert child.returncode == -signal.SIGKILL and m.running() == []
    finally:
        sbm.STOP_TIMEOUT_SEC = stop_timeout
        env.close()


def test_manager_ignores_stale_pid_files():
    env = Env()
    try:
        run = os.path.join(env.dir, "run")
        os.makedirs(run)
        with open(os.path.join(run, "vd-old.pid"), "w") as f:
            f.write("999999")
        with open(os.path.join(run, "vd-junk.pid"), "w") as f:
            f.write("not a pid")
        assert env.manager.running() == [] and env.manager.pid("vd-old") is None
        # On Linux a recycled PID of another program does not count either.
        if os.path.isdir("/proc"):
            with open(os.path.join(run, "vd-self.pid"), "w") as f:
                f.write(str(os.getpid()))
            assert SingBoxManager(env.manager.binary_manager, run_dir=run).pid("vd-self") is None
            os.unlink(os.path.join(run, "vd-self.pid"))
    finally:
        env.close()


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        started = time.monotonic()
        t()
        print(f"✓ {t.__name__} ({time.monotonic() - started:.1f}s)")
    print(f"\n✅ sing-box tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
