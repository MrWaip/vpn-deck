"""
BinaryManager - Manages detection and access to AmneziaWG binaries
"""

import os
import subprocess
import re
from typing import Optional, Dict

import decky


class BinaryManager:
    """Manages detection and access to AmneziaWG binaries"""
    
    def __init__(self):
        """Initialize BinaryManager"""
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))
        self.bin_dir = os.path.join(self.plugin_dir, "..", "..", "bin")
        self.binary_cache: Optional[Dict[str, str]] = None

        # Binary names we're looking for
        self.binary_names = ["amneziawg-go", "awg", "awg-quick", "sing-box"]
    
    def detect_binaries(self) -> Dict[str, Optional[str]]:
        """
        Detects where AmneziaWG binaries are located.
        
        Returns:
            Dictionary mapping binary name to path (or None if not found)
            Example: {"amneziawg-go": "/usr/bin/amneziawg-go", "awg": "/usr/bin/awg", ...}
        """
        if self.binary_cache is not None:
            return self.binary_cache
        
        binaries: Dict[str, Optional[str]] = {}

        for binary_name in self.binary_names:
            potential_path = os.path.join(self.bin_dir, binary_name)

            if os.path.isfile(potential_path) and os.access(potential_path, os.X_OK):
                decky.logger.info(f"Found {binary_name} at {potential_path}")
                binaries[binary_name] = potential_path
            else:
                decky.logger.error(f"Binary {binary_name} not found in {self.bin_dir}")
                binaries[binary_name] = None
        
        # Cache the results
        self.binary_cache = binaries
        return binaries
    
    def get_binary_path(self, name: str) -> Optional[str]:
        """
        Gets the path to a specific binary.
        
        Args:
            name: Binary name (e.g., "amneziawg-go", "awg", "awg-quick")
        
        Returns:
            Path to the binary, or None if not found
        """
        if self.binary_cache is None:
            self.detect_binaries()
        
        return self.binary_cache.get(name) if self.binary_cache else None
    
    @staticmethod
    def _extract_version(output: str) -> Optional[str]:
        """Extracts a version string like 'v1.2.3' or '1.2.3' from command output."""
        match = re.search(r'v?(\d+\.\d+\.\d+|\d+\.\d+)', output)
        if match:
            return match.group(0)
        return output.split('\n')[0] if output else None

    def check_binary_version(self, path: str) -> Optional[str]:
        """Checks the version of a binary."""
        if not os.path.isfile(path):
            return None

        try:
            for flag in ("--version", "-v", "version"):
                result = subprocess.run(
                    [path, flag],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                if result.returncode == 0 and result.stdout:
                    return self._extract_version(result.stdout.strip())

            decky.logger.warning(f"Could not determine version for {path}")
            return "unknown"

        except subprocess.TimeoutExpired:
            decky.logger.error(f"Timeout checking version for {path}")
            return None
        except Exception as e:
            decky.logger.error(f"Error checking version for {path}: {e}")
            return None
    
    def invalidate_cache(self):
        """Invalidates the binary cache, forcing a re-detection on next access"""
        self.binary_cache = None
        decky.logger.info("Binary cache invalidated")
    
    def get_binaries_info(self) -> Dict[str, Dict[str, Optional[str]]]:
        """
        Gets detailed information about all binaries.
        
        Returns:
            Dictionary with binary info including path and version
            Example: {
                "amneziawg-go": {"path": "/usr/bin/amneziawg-go", "version": "1.0.0"},
                "awg": {"path": "/usr/bin/awg", "version": "1.0.0"},
                ...
            }
        """
        binaries = self.detect_binaries()
        info = {}
        
        for name, path in binaries.items():
            if path:
                version = self.check_binary_version(path)
                info[name] = {"path": path, "version": version}
            else:
                info[name] = {"path": None, "version": None}
        
        return info
