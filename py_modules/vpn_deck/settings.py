"""
Settings - Small persistent plugin settings, a JSON file in the Decky settings directory
"""

import json
import os
from typing import Any, Optional

import decky

DEFAULTS = {
    # Bring the config that was on at shutdown back up when the plugin starts.
    "restore_on_boot": True,
    "last_active": None,
}


class Settings:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.path.join(decky.DECKY_PLUGIN_SETTINGS_DIR, "settings.json")
        self.data = dict(DEFAULTS)
        try:
            with open(self.path) as f:
                stored = json.load(f)
        except (OSError, ValueError):
            stored = None
        if isinstance(stored, dict):
            self.data.update({k: v for k, v in stored.items() if k in DEFAULTS})

    def get(self, key: str) -> Any:
        return self.data[key]

    def set(self, key: str, value: Any) -> None:
        if self.data.get(key) == value:
            return
        self.data[key] = value
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp_path = f"{self.path}.tmp"
            with open(tmp_path, "w") as f:
                json.dump(self.data, f)
            os.replace(tmp_path, self.path)
        except OSError as e:
            decky.logger.warning(f"Failed to save settings to {self.path}: {e}")
