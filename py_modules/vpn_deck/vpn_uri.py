"""
Decoding of AmneziaVPN share links (vpn://...) into native AmneziaWG/WireGuard configs.
"""

import base64
import ipaddress
import json
import zlib
from typing import Optional

VPN_URI_PREFIX = "vpn://"
_PROTOCOLS = ("awg", "wireguard")
_DEFAULT_DNS = ("1.1.1.1", "1.0.0.1")
_MAX_JSON_SIZE = 1 << 20


class VpnUriError(ValueError):
    pass


def _strip(content: str) -> str:
    return content.strip().lstrip("\ufeff").strip()


def is_vpn_uri(content: str) -> bool:
    """True if the text is a vpn:// link (a leading BOM and whitespace are ignored)."""
    return _strip(content).startswith(VPN_URI_PREFIX)


def looks_like_wg_config(text: str) -> bool:
    """True if the text has [Interface] and [Peer] headers on their own lines, case-insensitive."""
    # Like awg-quick, drop "# comment" tails before matching, so "[Peer] # server" still counts.
    lines = {line.split("#", 1)[0].strip().lower() for line in text.splitlines()}
    return "[interface]" in lines and "[peer]" in lines


def _unpack(content: str) -> dict:
    text = _strip(content)
    if not text.startswith(VPN_URI_PREFIX):
        raise VpnUriError("это не ссылка vpn://")
    payload = "".join(text[len(VPN_URI_PREFIX):].split())
    payload += "=" * (-len(payload) % 4)
    try:
        raw = base64.b64decode(payload.replace("-", "+").replace("_", "/"), validate=True)
    except ValueError as e:
        raise VpnUriError(f"ссылка не в base64: {e}")

    # qCompress: 4-byte big-endian size, then zlib; the app also accepts uncompressed JSON
    try:
        inflater = zlib.decompressobj()
        inflated = inflater.decompress(raw[4:], _MAX_JSON_SIZE)
        if inflater.unconsumed_tail:
            raise VpnUriError("ссылка распаковывается больше чем в 1 МБ, это не похоже на конфиг")
        raw = inflated
    except zlib.error:
        pass

    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as e:
        raise VpnUriError(f"внутри ссылки не JSON: {e}")
    if not isinstance(data, dict):
        raise VpnUriError("внутри ссылки не объект JSON")
    return data


def _native_config(protocol_config: dict) -> Optional[str]:
    last_config = protocol_config.get("last_config")
    if not isinstance(last_config, str):
        return None
    try:
        parsed = json.loads(last_config)
    except (ValueError, RecursionError):
        parsed = None
    config = parsed.get("config") if isinstance(parsed, dict) else last_config
    return config if isinstance(config, str) and looks_like_wg_config(config) else None


def _dns(value: object, default: str) -> str:
    # Same rule as the AmneziaVPN client for an imported link: IPv4 or the app default.
    # AmneziaDNS (172.29.172.254) needs no special case, the exporting app already puts it into dns1.
    if isinstance(value, str) and value.count(".") == 3:
        try:
            ipaddress.IPv4Address(value)
            return value
        except ValueError:
            pass
    return default


def decode_vpn_uri(content: str) -> str:
    """Returns the native .conf text from an AmneziaVPN vpn:// link."""
    data = _unpack(content)

    containers = data.get("containers")
    if not isinstance(containers, list):
        raise VpnUriError("в ссылке нет списка контейнеров")
    containers = [c for c in containers if isinstance(c, dict)]
    default = data.get("defaultContainer")
    containers.sort(key=lambda c: c.get("container") != default)

    for container in containers:
        for proto in _PROTOCOLS:
            protocol_config = container.get(proto)
            if not isinstance(protocol_config, dict):
                continue
            config = _native_config(protocol_config)
            if config:
                dns1 = _dns(data.get("dns1"), _DEFAULT_DNS[0])
                dns2 = _dns(data.get("dns2"), _DEFAULT_DNS[1])
                return config.replace("$PRIMARY_DNS", dns1).replace("$SECONDARY_DNS", dns2)

    raise VpnUriError("в ссылке нет конфига AmneziaWG или WireGuard")
