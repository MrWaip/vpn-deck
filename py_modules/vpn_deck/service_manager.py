"""
ServiceManager - Manages AmneziaWG interface lifecycle via awg-quick
"""

import os
import subprocess
import threading
from datetime import datetime

import decky

from ._utils import clean_env

MANAGED_PREFIX = "vd-"
DEFAULT_INTERFACE = "awg0"

# awg-quick up/down может долго выполняться (маршруты, DNS, резолвы)
START_STOP_TIMEOUT_SEC = 60
AWG_QUICK_LOG = os.path.join(decky.DECKY_PLUGIN_LOG_DIR, "awg-quick.log")


class ServiceManager:
    def __init__(self, binary_manager):
        self.binary_manager = binary_manager
        # Serializes awg-quick up/down between RPC handlers and NetworkWatch's worker thread.
        self.lock = threading.RLock()

    def run_command(self, cmd: list, timeout: int = 10):
        """Runs a helper command without info logging: (returncode, stdout, stderr)."""
        return self._run(cmd, timeout=timeout, quiet=True)

    def _run(self, cmd: list, timeout: int = 10, quiet: bool = False):
        log = decky.logger.debug if quiet else decky.logger.info
        log(f"Running: {' '.join(str(c) for c in cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=clean_env()
            )
            return (result.returncode, result.stdout.strip(), result.stderr.strip())
        except subprocess.TimeoutExpired:
            decky.logger.warning(
                f"Command timed out after {timeout}s: {' '.join(str(c) for c in cmd)}"
            )
            return (1, "", f"timeout after {timeout}s")
        except FileNotFoundError:
            decky.logger.warning(f"Command not found: {cmd[0]}")
            return (127, "", f"{cmd[0]}: command not found")

    def _run_logged(self, cmd: list, timeout: int = 60):
        """Run a long-lived command with output redirected to a log file.

        awg-quick spawns background processes that inherit pipe FDs,
        causing subprocess.run with capture_output=True to hang.
        Writing to a file + start_new_session avoids this.
        """
        cmd_str = ' '.join(str(c) for c in cmd)
        decky.logger.info(f"Running (logged): {cmd_str}")
        try:
            with open(AWG_QUICK_LOG, "a") as log_file:
                log_file.write(f"\n--- {datetime.now().isoformat()} | {cmd_str} ---\n")
                log_file.flush()
                result = subprocess.run(
                    cmd,
                    stdout=log_file,
                    stderr=log_file,
                    text=True,
                    timeout=timeout,
                    start_new_session=True,
                    env=clean_env(),
                )
                log_file.write(f"--- RC: {result.returncode} ---\n")

            # Read tail of log for error reporting
            stderr = ""
            if result.returncode != 0:
                try:
                    with open(AWG_QUICK_LOG, "r") as f:
                        lines = f.readlines()
                        stderr = "".join(lines[-20:]).strip()
                except OSError:
                    pass

            return (result.returncode, "", stderr)
        except subprocess.TimeoutExpired:
            decky.logger.warning(f"Command timed out after {timeout}s: {cmd_str}")
            return (1, "", f"timeout after {timeout}s")
        except FileNotFoundError:
            decky.logger.warning(f"Command not found: {cmd[0]}")
            return (127, "", f"{cmd[0]}: command not found")

    # ── Why _run_logged instead of _run for start/stop ──────────────
    # awg-quick is a bash script that spawns `amneziawg-go` as a
    # background daemon.  The daemon inherits pipe FDs created by
    # subprocess.run(capture_output=True), so the parent process
    # blocks forever waiting for EOF on those pipes.
    #
    # _run_logged redirects output to a file and uses
    # start_new_session=True so child processes don't inherit our FDs.
    # ─────────────────────────────────────────────────────────────────

    def start_interface(self, interface: str) -> dict:
        awg_quick_path = self.binary_manager.get_binary_path("awg-quick")
        if awg_quick_path is None:
            return {"success": False, "interface": interface, "method": None, "error": "awg-quick binary not found"}

        with self.lock:
            rc, _, stderr = self._run_logged(
                [awg_quick_path, "up", interface],
                timeout=START_STOP_TIMEOUT_SEC,
            )
        if rc == 0:
            decky.logger.info(f"Started {interface} via awg-quick")
            return {"success": True, "interface": interface, "method": "awg-quick", "error": None}

        err_msg = stderr or f"awg-quick up failed (rc={rc})"
        decky.logger.error(f"Failed to start {interface}: {err_msg}")
        return {"success": False, "interface": interface, "method": "awg-quick", "error": err_msg}

    def stop_interface(self, interface: str) -> dict:
        awg_quick_path = self.binary_manager.get_binary_path("awg-quick")
        if awg_quick_path is None:
            return {"success": False, "interface": interface, "method": None, "error": "awg-quick binary not found"}

        with self.lock:
            rc, _, stderr = self._run_logged(
                [awg_quick_path, "down", interface],
                timeout=START_STOP_TIMEOUT_SEC,
            )
        if rc == 0:
            decky.logger.info(f"Stopped {interface} via awg-quick")
            return {"success": True, "interface": interface, "method": "awg-quick", "error": None}

        decky.logger.error(f"Failed to stop {interface}: {stderr}")
        return {"success": False, "interface": interface, "method": "awg-quick", "error": stderr or f"awg-quick down failed (rc={rc})"}

    def get_status(self, interface: str) -> dict:
        awg_path = self.binary_manager.get_binary_path("awg")

        if awg_path:
            rc, stdout, _ = self._run([awg_path, "show", interface], quiet=True)
            is_up = rc == 0
            peers = self._parse_awg_show(stdout) if is_up else []
            status = "active" if is_up else "inactive"
        else:
            decky.logger.warning("awg binary not found, cannot get interface status")
            peers = []
            status = "unknown"

        return {
            "interface": interface,
            "status": status,
            "peers": peers,
        }

    def _parse_awg_show(self, output: str) -> list:
        peers = []
        current_peer = None

        for line in output.splitlines():
            if line.startswith("peer:"):
                if current_peer is not None:
                    peers.append(current_peer)
                current_peer = {
                    "public_key": line[len("peer:"):].strip(),
                    "endpoint": None,
                    "latest_handshake": None,
                    "transfer_rx": None,
                    "transfer_tx": None,
                }
            elif current_peer is not None:
                stripped = line.strip()
                if stripped.startswith("endpoint:"):
                    current_peer["endpoint"] = stripped[len("endpoint:"):].strip()
                elif stripped.startswith("latest handshake:"):
                    current_peer["latest_handshake"] = stripped[len("latest handshake:"):].strip()
                elif stripped.startswith("transfer:"):
                    transfer = stripped[len("transfer:"):].strip()
                    # "1.23 MiB received, 456 KiB sent"
                    parts = transfer.split(",")
                    for part in parts:
                        part = part.strip()
                        if "received" in part:
                            current_peer["transfer_rx"] = part.replace("received", "").strip()
                        elif "sent" in part:
                            current_peer["transfer_tx"] = part.replace("sent", "").strip()

        if current_peer is not None:
            peers.append(current_peer)

        return peers

    def get_all_statuses(self) -> list:
        awg_path = self.binary_manager.get_binary_path("awg")
        if awg_path is None:
            decky.logger.warning("awg binary not found, cannot list interfaces")
            return []

        return [self.get_status(iface) for iface in self.list_interfaces()]

    def list_interfaces(self) -> list:
        awg_path = self.binary_manager.get_binary_path("awg")
        if awg_path is None:
            return []
        rc, stdout, _ = self._run([awg_path, "show", "interfaces"], quiet=True)
        return stdout.split() if rc == 0 and stdout else []

    def stop_all_interfaces(self, only_managed: bool = False) -> dict:
        awg_path = self.binary_manager.get_binary_path("awg")
        if awg_path is None:
            return {"stopped": [], "failed": [], "total": 0}

        rc, stdout, _ = self._run([awg_path, "show", "interfaces"])
        ifaces = stdout.split() if rc == 0 and stdout else []

        if only_managed:
            ifaces = [i for i in ifaces if i.startswith(MANAGED_PREFIX)]

        stopped = []
        failed = []
        for iface in ifaces:
            result = self.stop_interface(iface)
            if result["success"]:
                stopped.append(iface)
            else:
                failed.append(iface)

        return {"stopped": stopped, "failed": failed, "total": len(ifaces)}
