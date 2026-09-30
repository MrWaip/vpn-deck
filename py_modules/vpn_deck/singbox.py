"""
sing-box configs for a whole-device tunnel: from a vless:// link or a ready sing-box JSON config.
"""

import json
from typing import Optional
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlsplit

VLESS_PREFIX = "vless://"
PROXY_TAG = "proxy"
SERVER_RESOLVER_TAG = "server"
TUN_ADDRESS = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
REMOTE_DNS = "1.1.1.1"
_SERVICE_OUTBOUNDS = {"direct", "block", "dns", "selector", "urltest"}
_TRUE = {"1", "true", "yes"}


class SingBoxError(ValueError):
    pass


def _strip(content: str) -> str:
    return content.strip().lstrip("﻿").strip()


def is_vless_uri(content: str) -> bool:
    return _strip(content)[:len(VLESS_PREFIX)].lower() == VLESS_PREFIX


def looks_like_json(content: str) -> bool:
    return _strip(content).startswith("{")


def _ws_transport(path: str, host: str) -> dict:
    transport = {"type": "ws", "path": path or "/"}
    # xray puts early data into the path as "?ed=2048"; sing-box has separate fields for it.
    base, _, query = transport["path"].partition("?")
    params = parse_qsl(query, keep_blank_values=True)
    early = dict(params).get("ed", "")
    if early.isdigit():
        rest = urlencode([(k, v) for k, v in params if k != "ed"])
        transport["path"] = (base or "/") + (f"?{rest}" if rest else "")
        transport["max_early_data"] = int(early)
        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
    if host:
        transport["headers"] = {"Host": host}
    return transport


def vless_link(content: str) -> str:
    """The single vless:// link from a file, as it is stored."""
    lines = [line.strip() for line in _strip(content).splitlines() if line.strip()]
    if len(lines) != 1:
        raise SingBoxError("в файле должна быть одна ссылка vless://, без других строк")
    # The #remark is only a label and may contain spaces; the link itself may not.
    if len(lines[0].partition("#")[0].split()) > 1:
        raise SingBoxError("в ссылке vless:// есть пробелы")
    return lines[0]


def vless_outbound(content: str) -> dict:
    """sing-box outbound for a vless:// link in the xray share format."""
    link = vless_link(content).partition("#")[0]
    try:
        url = urlsplit(link)
        port = url.port or 443
    except ValueError as e:
        raise SingBoxError(f"не удалось разобрать ссылку vless://: {e}")
    if url.scheme.lower() != "vless":
        raise SingBoxError("это не ссылка vless://")
    uuid = unquote(url.username or "")
    if not uuid:
        raise SingBoxError("в ссылке нет UUID")
    if not url.hostname:
        raise SingBoxError("в ссылке нет адреса сервера")

    q = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
    encryption = q.get("encryption", "none")
    if encryption not in ("", "none"):
        raise SingBoxError(f"шифрование VLESS {encryption} sing-box не поддерживает")

    outbound = {"type": "vless", "tag": PROXY_TAG, "server": url.hostname, "server_port": port, "uuid": uuid}
    if q.get("flow"):
        outbound["flow"] = q["flow"]

    host = q.get("host", "")
    security = q.get("security", "none") or "none"
    if security in ("tls", "reality"):
        tls = {"enabled": True, "server_name": q.get("sni") or host or url.hostname}
        if q.get("alpn"):
            tls["alpn"] = [a for a in q["alpn"].split(",") if a]
        if q.get("allowInsecure", q.get("insecure", "")).lower() in _TRUE:
            tls["insecure"] = True
        fingerprint = q.get("fp", "")
        if security == "reality":
            if not q.get("pbk"):
                raise SingBoxError("в ссылке REALITY нет публичного ключа (pbk)")
            tls["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": q.get("sid", "")}
            fingerprint = fingerprint or "chrome"  # sing-box needs uTLS for REALITY
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        outbound["tls"] = tls
    elif security != "none":
        raise SingBoxError(f"security={security} sing-box не поддерживает")

    network = q.get("type", "tcp") or "tcp"
    path = q.get("path", "")
    if network == "ws":
        outbound["transport"] = _ws_transport(path, host)
    elif network == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif network == "httpupgrade":
        outbound["transport"] = {"type": "httpupgrade", "path": path or "/"}
        if host:
            outbound["transport"]["host"] = host
    elif network in ("http", "h2"):
        outbound["transport"] = {"type": "http", "path": path or "/"}
        if host:
            outbound["transport"]["host"] = [h for h in host.split(",") if h]
    elif network in ("tcp", "raw"):
        if q.get("headerType", "none") not in ("", "none"):
            raise SingBoxError(f"маскировку TCP headerType={q['headerType']} sing-box не поддерживает")
    else:
        raise SingBoxError(f"транспорт type={network} sing-box не поддерживает")
    return outbound


def tun_config(outbound: dict, interface: str, server_address: Optional[str] = None) -> dict:
    """Whole-device tunnel: everything but private addresses goes through the proxy, all DNS too.

    server_address is the proxy server's IP, resolved before the tunnel exists. Otherwise sing-box
    resolves the name through systemd-resolved, whose queries come back into the tunnel and need the
    very proxy they are resolving. The name stays in the outbound for TLS SNI and the Host header.
    """
    servers = [
        {"type": "https", "tag": "remote", "server": REMOTE_DNS, "detour": PROXY_TAG},
        {"type": "local", "tag": "local"},
    ]
    if server_address and server_address != outbound["server"]:
        servers.append({"type": "hosts", "tag": SERVER_RESOLVER_TAG,
                        "predefined": {outbound["server"]: [server_address]}})
        outbound = dict(outbound, domain_resolver=SERVER_RESOLVER_TAG)
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": servers,
            "final": "remote",
            # IPv6 is captured by the tunnel too; A records only keep apps off a v6 path the server may lack.
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": interface,
            "address": TUN_ADDRESS,
            "auto_route": True,
            "strict_route": True,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": PROXY_TAG,
            "auto_detect_interface": True,
            "default_domain_resolver": "local",
        },
    }


def _user_config(content: str, interface: str) -> dict:
    try:
        config = json.loads(_strip(content))
    except (ValueError, RecursionError) as e:
        raise SingBoxError(f"файл не JSON: {e}")
    if not isinstance(config, dict):
        raise SingBoxError("в файле не объект JSON")
    sections = [config.get("inbounds"), config.get("outbounds")]
    if any(isinstance(item, dict) and "protocol" in item for section in sections if isinstance(section, list) for item in section):
        raise SingBoxError("это конфиг xray, а не sing-box: импортируй вместо него ссылку vless://")
    inbounds = config.get("inbounds")
    tuns = [i for i in inbounds if isinstance(i, dict) and i.get("type") == "tun"] if isinstance(inbounds, list) else []
    if len(tuns) != 1:
        raise SingBoxError("в конфиге sing-box должен быть ровно один inbound с type tun, "
                           "без него туннель не заворачивает трафик Deck")
    # The plugin finds the running tunnel by this name.
    tuns[0]["interface_name"] = interface
    return config


def singbox_config(content: str, interface: str) -> dict:
    """sing-box config from a file with a vless:// link or with a sing-box JSON config."""
    if is_vless_uri(content):
        return tun_config(vless_outbound(content), interface)
    if looks_like_json(content):
        return _user_config(content, interface)
    raise SingBoxError("это не ссылка vless:// и не JSON sing-box")


def protocol_label(config: dict) -> Optional[str]:
    """'VLESS', 'TROJAN'... from the first proxy outbound, for the config list."""
    outbounds = config.get("outbounds") if isinstance(config, dict) else None
    for outbound in outbounds if isinstance(outbounds, list) else []:
        kind = outbound.get("type") if isinstance(outbound, dict) else None
        if isinstance(kind, str) and kind not in _SERVICE_OUTBOUNDS:
            return kind.upper()
    return None
