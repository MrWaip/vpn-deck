"""
ConfigManager - Manages VPN configurations with import and validation
"""

import json
import os
import re
from typing import Optional, Dict, List

import decky

from .singbox import protocol_label


class ConfigManager:
    """Manages VPN configurations with import and validation"""

    def __init__(self):
        # Directories
        self.config_dir = os.path.expanduser("~/.local/share/vpn-deck/configs")
        self.system_config_dir = "/etc/amnezia/amneziawg"

        # Prefix for managed configs (short to leave room for user name; IFNAMSIZ=16)
        self.config_prefix = "vd-"

        # Ensure directories exist
        self._ensure_directories()

    def _ensure_directories(self):
        """Creates necessary directories if they don't exist"""
        for directory in [self.config_dir]:
            try:
                os.makedirs(directory, mode=0o700, exist_ok=True)
                decky.logger.info(f"Ensured directory exists: {directory}")
            except Exception as e:
                decky.logger.error(f"Failed to create directory {directory}: {e}")
    
    def _sanitize_name(self, name: str) -> str:
        """
        Sanitizes config name to be filesystem-safe.
        
        Args:
            name: Raw config name
        
        Returns:
            Sanitized name (only a-z, 0-9, -, _)
        """
        # Remove any path separators
        name = os.path.basename(name)
        # Remove .conf extension if present
        if name.endswith('.conf'):
            name = name[:-5]
        # Keep only alphanumeric, dash, underscore
        sanitized = re.sub(r'[^a-zA-Z0-9\-_]', '-', name)
        # Remove multiple consecutive dashes
        sanitized = re.sub(r'-+', '-', sanitized)
        # Remove leading/trailing dashes
        sanitized = sanitized.strip('-')
        # Convert to lowercase
        sanitized = sanitized.lower()
        
        if not sanitized:
            sanitized = "config"

        decky.logger.info(f"Sanitized config name '{name}' to '{sanitized}'")
        return sanitized

    def get_interface_name(self, name: str) -> str:
        return f"{self.config_prefix}{self._sanitize_name(name)}"

    _EXTENSIONS = {"awg": "conf", "sing-box": "json", "vless": "vless"}

    def config_type(self, name: str) -> Optional[str]:
        """"awg" for a .conf, "sing-box" for a .json, "vless" for a stored vless:// link, None if absent."""
        base = os.path.join(self.config_dir, self._sanitize_name(name))
        for kind, ext in self._EXTENSIONS.items():
            if os.path.isfile(f"{base}.{ext}"):
                return kind
        return None

    def config_path(self, name: str) -> str:
        ext = self._EXTENSIONS.get(self.config_type(name), "conf")
        return os.path.join(self.config_dir, f"{self._sanitize_name(name)}.{ext}")

    def _singbox_protocol(self, path: str) -> str:
        try:
            with open(path) as f:
                return protocol_label(json.load(f)) or "sing-box"
        except (OSError, ValueError, RecursionError):
            return "sing-box"

    async def scan_existing_configs(self) -> Dict[str, List[Dict]]:
        """
        Scans for all VPN configurations (managed and user-created).
        
        Returns:
            Dictionary with 'managed' and 'existing' config lists
        """
        result = {
            "managed": [],
            "existing": []
        }
        
        try:
            # Scan managed configs in our config directory
            if os.path.isdir(self.config_dir):
                for filename in os.listdir(self.config_dir):
                    if filename.endswith('.conf'):
                        name = filename[:-5]
                        local_path = os.path.join(self.config_dir, filename)
                        interface_name = f"{self.config_prefix}{name}"
                        system_path = os.path.join(self.system_config_dir, f"{interface_name}.conf")
                        
                        is_symlink = False
                        if os.path.islink(system_path):
                            is_symlink = True
                        
                        result["managed"].append({
                            "name": name,
                            "interface": interface_name,
                            "path": local_path,
                            "system_path": system_path,
                            "is_symlink": is_symlink,
                            "managed_by": "vpn-deck",
                            "type": "awg",
                            "protocol": "AWG",
                        })
                    elif filename.endswith(('.json', '.vless')):
                        name, ext = os.path.splitext(filename)
                        local_path = os.path.join(self.config_dir, filename)
                        vless = ext == '.vless'
                        result["managed"].append({
                            "name": name,
                            "interface": f"{self.config_prefix}{name}",
                            "path": local_path,
                            "system_path": None,
                            "is_symlink": False,
                            "managed_by": "vpn-deck",
                            "type": "vless" if vless else "sing-box",
                            "protocol": "VLESS" if vless else self._singbox_protocol(local_path),
                        })
            
            # Scan existing configs in system directory
            if os.path.isdir(self.system_config_dir):
                for filename in os.listdir(self.system_config_dir):
                    if filename.endswith('.conf') and not filename.startswith(self.config_prefix):
                        name = filename[:-5]
                        system_path = os.path.join(self.system_config_dir, filename)
                        
                        # Skip if it's a symlink to our managed configs
                        if os.path.islink(system_path):
                            target = os.readlink(system_path)
                            if target.startswith(self.config_dir):
                                continue
                        
                        result["existing"].append({
                            "name": name,
                            "interface": name,
                            "path": system_path,
                            "managed_by": "user"
                        })
            
            decky.logger.debug(f"Found {len(result['managed'])} managed and {len(result['existing'])} existing configs")
            
        except Exception as e:
            decky.logger.error(f"Error scanning configs: {e}")
        
        return result
    
    async def list_all_configs(self) -> List[Dict]:
        """Returns a flat list of all configurations"""
        scanned = await self.scan_existing_configs()
        all_configs = scanned["managed"] + scanned["existing"]
        return all_configs
    
    async def get_config_content(self, name: str) -> Optional[str]:
        """Reads and returns the content of a configuration file"""
        config_path = self.config_path(name)

        try:
            if not os.path.isfile(config_path):
                decky.logger.warning(f"Config file not found: {config_path}")
                return None
            
            with open(config_path, 'r') as f:
                content = f.read()
            
            decky.logger.info(f"Read config content from {config_path}")
            return content
            
        except Exception as e:
            decky.logger.error(f"Error reading config {config_path}: {e}")
            return None
    
    def _ensure_symlink(self, local_path: str, system_path: str) -> Dict:
        """Makes sure system_path is a symlink pointing at local_path.

        Steam OS updates wipe /etc/amnezia/amneziawg/*, so this is called
        both on import and on plugin load to repair links that slipped.
        Returns {"ok": bool, "action": "none"|"created"|"replaced", "error": str|None}.
        """
        try:
            os.makedirs(os.path.dirname(system_path), mode=0o755, exist_ok=True)

            try:
                if os.readlink(system_path) == local_path:
                    return {"ok": True, "action": "none", "error": None}
                existed = True
            except OSError:
                existed = os.path.lexists(system_path)

            if existed:
                try:
                    os.unlink(system_path)
                except FileNotFoundError:
                    existed = False

            os.symlink(local_path, system_path)
            action = "replaced" if existed else "created"
            decky.logger.info(f"Symlink {action}: {system_path} -> {local_path}")
            return {"ok": True, "action": action, "error": None}
        except Exception as e:
            decky.logger.warning(f"Symlink failed for {system_path}: {e}")
            return {"ok": False, "action": "error", "error": str(e)}

    def write_config(self, name: str, content: str) -> Dict:
        """Writes config to local store and creates symlink in system directory."""
        sanitized_name = self._sanitize_name(name)
        local_path = os.path.join(self.config_dir, f"{sanitized_name}.conf")
        interface_name = f"{self.config_prefix}{sanitized_name}"
        system_path = os.path.join(self.system_config_dir, f"{interface_name}.conf")

        with open(local_path, "w") as f:
            f.write(content)
        os.chmod(local_path, 0o600)
        decky.logger.info(f"Wrote config to {local_path}")

        self._ensure_symlink(local_path, system_path)

        return {"success": True, "config_name": sanitized_name, "interface_name": interface_name, "error": None}

    def _write_singbox_file(self, name: str, ext: str, text: str) -> Dict:
        """sing-box configs live only in the local store, no symlink; a .json and a .vless never coexist."""
        sanitized_name = self._sanitize_name(name)
        local_path = os.path.join(self.config_dir, f"{sanitized_name}.{ext}")
        tmp_path = f"{local_path}.tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp_path, local_path)
        other = os.path.join(self.config_dir, f"{sanitized_name}.{'json' if ext == 'vless' else 'vless'}")
        if os.path.exists(other):
            os.unlink(other)
        decky.logger.info(f"Wrote sing-box config to {local_path}")
        return {"success": True, "config_name": sanitized_name,
                "interface_name": f"{self.config_prefix}{sanitized_name}", "error": None}

    def write_singbox_config(self, name: str, config: dict) -> Dict:
        return self._write_singbox_file(name, "json", json.dumps(config, indent=2, ensure_ascii=False))

    def write_vless_link(self, name: str, link: str) -> Dict:
        """Stores the link itself: the tunnel config is built from it on every start."""
        return self._write_singbox_file(name, "vless", link + "\n")

    async def repair_symlinks(self) -> Dict:
        """Re-creates missing/broken symlinks for all managed configs."""
        scanned = await self.scan_existing_configs()
        results = []
        for cfg in scanned["managed"]:
            if cfg["type"] != "awg":
                continue
            r = self._ensure_symlink(cfg["path"], cfg["system_path"])
            results.append({
                "name": cfg["name"],
                "interface": cfg["interface"],
                "ok": r["ok"],
                "action": r["action"],
                "error": r["error"],
            })
        repaired = sum(1 for r in results if r["ok"] and r["action"] in ("created", "replaced"))
        return {"total": len(results), "repaired": repaired, "results": results}

    async def delete_config(self, name: str) -> Dict:
        """Deletes a VPN configuration (no backup)."""
        result = {
            "success": False,
            "config_name": None,
            "symlink_removed": False,
            "error": None
        }

        try:
            sanitized_name = self._sanitize_name(name)
            result["config_name"] = sanitized_name

            local_path = self.config_path(sanitized_name)
            interface_name = f"{self.config_prefix}{sanitized_name}"
            system_path = os.path.join(self.system_config_dir, f"{interface_name}.conf")

            if not os.path.exists(local_path):
                result["error"] = f"Config '{sanitized_name}' not found"
                return result

            os.unlink(local_path)
            decky.logger.info(f"Deleted config file: {local_path}")
            
            if os.path.islink(system_path):
                try:
                    os.unlink(system_path)
                    result["symlink_removed"] = True
                    decky.logger.info(f"Removed symlink: {system_path}")
                except Exception as e:
                    decky.logger.warning(f"Failed to remove symlink {system_path}: {e}")
            
            result["success"] = True
            decky.logger.info(f"Successfully deleted config: {sanitized_name}")
            
        except Exception as e:
            result["error"] = f"Deletion failed: {str(e)}"
            decky.logger.error(f"Error deleting config: {e}")

        return result
