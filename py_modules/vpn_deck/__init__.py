"""
VPN Deck - Plugin modules
"""

from .binary_manager import BinaryManager
from .config_manager import ConfigManager
from .diagnostics import Diagnostics
from .network_watch import NetworkWatch
from .service_manager import ServiceManager
from .settings import Settings
from .singbox import SingBoxError, is_vless_uri, looks_like_json, singbox_config, vless_link
from .singbox_manager import SingBoxManager
from .status import ConnectionStatus
from .vpn_uri import VpnUriError, decode_vpn_uri, is_vpn_uri, looks_like_wg_config

__all__ = ['BinaryManager', 'ConfigManager', 'ConnectionStatus', 'Diagnostics', 'NetworkWatch', 'ServiceManager',
           'Settings',
           'SingBoxError', 'SingBoxManager', 'is_vless_uri', 'looks_like_json', 'singbox_config', 'vless_link',
           'VpnUriError', 'decode_vpn_uri', 'is_vpn_uri', 'looks_like_wg_config']
