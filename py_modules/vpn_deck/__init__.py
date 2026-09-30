"""
VPN Deck - Plugin modules
"""

from .binary_manager import BinaryManager
from .config_manager import ConfigManager
from .diagnostics import Diagnostics
from .network_watch import NetworkWatch
from .service_manager import ServiceManager
from .vpn_uri import VpnUriError, decode_vpn_uri, is_vpn_uri, looks_like_wg_config

__all__ = ['BinaryManager', 'ConfigManager', 'Diagnostics', 'NetworkWatch', 'ServiceManager',
           'VpnUriError', 'decode_vpn_uri', 'is_vpn_uri', 'looks_like_wg_config']
