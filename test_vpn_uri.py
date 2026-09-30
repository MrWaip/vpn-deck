#!/usr/bin/env python3
"""
Unit tests for vpn:// link decoding (AmneziaVPN share links)
"""

import base64
import json
import os
import struct
import sys
import types
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_modules"))
_here = os.path.dirname(os.path.abspath(__file__))
sys.modules.setdefault("decky", types.SimpleNamespace(
    logger=types.SimpleNamespace(info=print, debug=print, warning=print, error=print),
    DECKY_PLUGIN_DIR=_here, DECKY_PLUGIN_LOG_DIR=os.path.join(_here, "logs")))

from vpn_deck.vpn_uri import VpnUriError, decode_vpn_uri, is_vpn_uri, looks_like_wg_config


NATIVE_CONFIG = """[Interface]
Address = 10.8.1.2/32
DNS = $PRIMARY_DNS, $SECONDARY_DNS
PrivateKey = YAnz5TF+lXXJte14tji3zlMNftft3UL32bbjzVEwPBs=
Jc = 4
Jmin = 10
Jmax = 50
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = jx1+44JyAAB8GqpR6ZzDVhT4Bq0D8dXdoIA6gFS9fho=

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:46907
PersistentKeepalive = 25
"""


def make_link(data: dict, compress: bool = True) -> str:
    raw = json.dumps(data).encode()
    if compress:
        raw = struct.pack(">I", len(raw)) + zlib.compress(raw)
    return "vpn://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def awg_container(last_config: str) -> dict:
    return {"container": "amnezia-awg", "awg": {"last_config": last_config, "port": "46907"}}


def app_export(dns1="1.1.1.1", dns2="9.9.9.9") -> dict:
    last_config = json.dumps({"config": NATIVE_CONFIG, "client_ip": "10.8.1.2"})
    return {
        "containers": [awg_container(last_config)],
        "defaultContainer": "amnezia-awg",
        "dns1": dns1,
        "dns2": dns2,
        "hostName": "vpn.example.com",
    }


def test_app_export():
    config = decode_vpn_uri(make_link(app_export()))
    assert config.startswith("[Interface]"), config
    assert "DNS = 1.1.1.1, 9.9.9.9" in config
    assert "$PRIMARY_DNS" not in config and "$SECONDARY_DNS" not in config
    assert "HeaderProtectionKey = " in config
    assert "Endpoint = vpn.example.com:46907" in config


def test_default_dns_when_missing():
    data = app_export()
    del data["dns1"], data["dns2"]
    assert "DNS = 1.1.1.1, 1.0.0.1" in decode_vpn_uri(make_link(data))


def test_raw_last_config():
    data = app_export()
    data["containers"] = [awg_container(NATIVE_CONFIG)]
    assert "DNS = 1.1.1.1, 9.9.9.9" in decode_vpn_uri(make_link(data))


def test_uncompressed_payload():
    assert decode_vpn_uri(make_link(app_export(), compress=False)).startswith("[Interface]")


def test_skips_other_protocols_and_prefers_default():
    data = app_export()
    xray = {"container": "amnezia-xray", "xray": {"last_config": "{}"}}
    wg_config = NATIVE_CONFIG.replace("46907", "51820")
    wg = {"container": "amnezia-wireguard", "wireguard": {"last_config": json.dumps({"config": wg_config})}}
    data["containers"] = [xray, wg] + data["containers"]
    assert "Endpoint = vpn.example.com:46907" in decode_vpn_uri(make_link(data))
    data["defaultContainer"] = "amnezia-wireguard"
    assert "Endpoint = vpn.example.com:51820" in decode_vpn_uri(make_link(data))


def test_whitespace_and_newlines_in_link():
    link = make_link(app_export())
    wrapped = "\n  " + "\n".join(link[i:i + 60] for i in range(0, len(link), 60)) + "\n"
    assert is_vpn_uri(wrapped)
    assert decode_vpn_uri(wrapped).startswith("[Interface]")


def test_errors():
    for bad, what in [
        ("vpn://!!!", "base64"),
        ("vpn://" + base64.urlsafe_b64encode(b"not json").decode(), "не JSON"),
        (make_link({"containers": [{"container": "amnezia-xray", "xray": {"last_config": "{}"}}]}), "нет конфига"),
    ]:
        try:
            decode_vpn_uri(bad)
        except VpnUriError as e:
            assert what in str(e), (what, str(e))
        else:
            raise AssertionError(f"ожидалась ошибка для {bad[:20]}")


def test_not_a_link():
    assert not is_vpn_uri(NATIVE_CONFIG)


def assert_vpn_error(link: str, what: str):
    try:
        decode_vpn_uri(link)
    except VpnUriError as e:
        assert what in str(e), (what, str(e))
    else:
        raise AssertionError(f"ожидалась ошибка «{what}» для {link[:30]}")


def test_containers_not_a_list():
    for containers in (None, {"amnezia-awg": {}}, "amnezia-awg"):
        assert_vpn_error(make_link({"containers": containers}), "нет списка контейнеров")
    assert_vpn_error(make_link({"defaultContainer": "amnezia-awg"}), "нет списка контейнеров")


def test_junk_containers_skipped():
    junk = [1, "amnezia-awg", None, [], {"container": "amnezia-awg"}, {"container": "amnezia-awg", "awg": "text"}]
    data = app_export()
    data["containers"] = junk + data["containers"]
    assert decode_vpn_uri(make_link(data)).startswith("[Interface]")
    data["containers"] = junk
    assert_vpn_error(make_link(data), "нет конфига")


def test_malformed_payload_shapes():
    assert_vpn_error("vpn://", "не JSON")
    assert_vpn_error(make_link([app_export()]), "не объект JSON")
    assert_vpn_error(make_link("[Interface]"), "не объект JSON")
    for awg in (["list"], {"last_config": 42}, {"last_config": None},
                {"last_config": json.dumps({"config": 42})},
                {"last_config": json.dumps(["[Interface]", "[Peer]"])}):
        assert_vpn_error(make_link({"containers": [{"container": "amnezia-awg", "awg": awg}]}), "нет конфига")


def test_deeply_nested_json():
    assert_vpn_error("vpn://" + base64.urlsafe_b64encode(b"[" * 200000).decode(), "не JSON")
    data = app_export()
    data["containers"] = [awg_container("[" * 200000)]
    assert_vpn_error(make_link(data), "нет конфига")


def test_zip_bomb_rejected():
    bomb = json.dumps({"containers": [], "pad": "A" * (2 << 20)}).encode()
    link = "vpn://" + base64.urlsafe_b64encode(struct.pack(">I", len(bomb)) + zlib.compress(bomb, 9)).decode()
    assert_vpn_error(link, "больше чем в 1 МБ")


def test_decode_requires_prefix():
    assert_vpn_error("hello world", "не ссылка vpn://")
    assert_vpn_error(NATIVE_CONFIG, "не ссылка vpn://")


def test_padded_link():
    for description in ("", "a", "ab"):
        data = dict(app_export(), description=description)
        link = "vpn://" + base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
        assert decode_vpn_uri(link).startswith("[Interface]"), link[-4:]


def test_bom_prefixed_link():
    link = make_link(app_export())
    assert is_vpn_uri("\ufeff" + link)
    assert decode_vpn_uri("\ufeff" + link).startswith("[Interface]")
    windows = "\ufeff" + "\r\n".join(link[i:i + 60] for i in range(0, len(link), 60)) + "\r\n"
    assert is_vpn_uri(windows)
    assert "DNS = 1.1.1.1, 9.9.9.9" in decode_vpn_uri(windows)


def test_dns_amnezia_dns_passes_through():
    assert "DNS = 172.29.172.254, 9.9.9.9" in decode_vpn_uri(make_link(app_export(dns1="172.29.172.254")))


def test_dns_non_ipv4_falls_back():
    for bad in (123, None, "", ["8.8.8.8"], "dns.google", "2606:4700:4700::1111", "::ffff:8.8.8.8",
                "300.1.1.1", "1.1.1", "8.8.8.8.8"):
        config = decode_vpn_uri(make_link(app_export(dns1=bad, dns2=bad)))
        assert "DNS = 1.1.1.1, 1.0.0.1" in config, bad


def test_dns_fields_are_independent():
    link = make_link(app_export(dns1="172.29.172.254", dns2="dns.google"))
    assert "DNS = 172.29.172.254, 1.0.0.1" in decode_vpn_uri(link)
    link = make_link(app_export(dns1=None, dns2="8.8.4.4"))
    assert "DNS = 1.1.1.1, 8.8.4.4" in decode_vpn_uri(link)


def test_config_without_peer_is_skipped():
    no_peer = NATIVE_CONFIG.split("[Peer]")[0]
    wg_config = NATIVE_CONFIG.replace("46907", "51820")
    wg = {"container": "amnezia-wireguard", "wireguard": {"last_config": json.dumps({"config": wg_config})}}
    data = app_export()

    data["containers"] = [awg_container(json.dumps({"config": no_peer})), wg]
    assert "Endpoint = vpn.example.com:51820" in decode_vpn_uri(make_link(data))

    both = {"container": "amnezia-awg", "awg": {"last_config": NATIVE_CONFIG}, "wireguard": {"last_config": wg_config}}
    data["containers"] = [both]
    assert "Endpoint = vpn.example.com:46907" in decode_vpn_uri(make_link(data))
    both["awg"]["last_config"] = no_peer
    assert "Endpoint = vpn.example.com:51820" in decode_vpn_uri(make_link(data))

    data["containers"] = [awg_container(no_peer), awg_container(json.dumps({"config": no_peer}))]
    assert_vpn_error(make_link(data), "нет конфига")


def test_looks_like_wg_config():
    assert looks_like_wg_config(NATIVE_CONFIG)
    assert looks_like_wg_config(NATIVE_CONFIG.replace("\n", "\r\n"))
    assert looks_like_wg_config("[interface]\nPrivateKey = x\n\n  [PEER]\t\nPublicKey = y\n")
    assert looks_like_wg_config("[Interface]  # home\nPrivateKey = x\n[Peer]# server\nPublicKey = y\n")

    assert not looks_like_wg_config(NATIVE_CONFIG.split("[Peer]")[0])
    assert not looks_like_wg_config(NATIVE_CONFIG.replace("[Interface]", ""))
    assert not looks_like_wg_config("[Interface] [Peer]")
    assert not looks_like_wg_config("# [Interface]\n# [Peer]\n")
    assert not looks_like_wg_config("Description = [Interface]\nNote = [Peer]\n")
    assert not looks_like_wg_config("")
    assert not looks_like_wg_config(make_link(app_export()))


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"✓ {t.__name__}")
    print(f"✅ vpn:// tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
