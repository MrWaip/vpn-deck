"""
SingBoxManager - Runs sing-box configs as whole-device TUN tunnels
"""

import ipaddress
import json
import os
import signal
import socket
import subprocess
import time
from typing import Callable, Dict, List, Optional

import decky

from ._utils import clean_env
from .singbox import SingBoxError, tun_config, vless_outbound

# tmpfs: PID files go away with a reboot, together with the tunnels.
RUN_DIR = "/run/vpn-deck"
NET_DIR = "/sys/class/net"
START_TIMEOUT_SEC = 10
# sing-box can still exit on route setup right after the TUN interface appears.
START_SETTLE_SEC = 0.5
# SIGKILL leaves sing-box's ip rules behind, so give it time to remove them itself.
STOP_TIMEOUT_SEC = 10
CHECK_TIMEOUT_SEC = 20
_LOG_TAIL_BYTES = 1500


def _result(interface: str, error: Optional[str] = None) -> dict:
    return {"success": error is None, "interface": interface, "method": "sing-box", "error": error}


def resolve_server(host: str, port: int) -> str:
    """IP of the proxy server via the system resolver, IPv4 first like the tunnel's DNS."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as e:
        raise SingBoxError(f"не удалось найти адрес сервера {host}: {e}")
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    return infos[0][4][0]


class SingBoxManager:
    def __init__(self, binary_manager, run_dir: str = RUN_DIR, log_dir: Optional[str] = None,
                 net_dir: str = NET_DIR, resolve: Callable[[str, int], str] = resolve_server):
        self.binary_manager = binary_manager
        self.run_dir = run_dir
        self.log_dir = log_dir or decky.DECKY_PLUGIN_LOG_DIR
        self.net_dir = net_dir
        self._resolve = resolve
        # Started by this process: kept to reap them, a tunnel from a previous plugin load is found by PID file.
        self._children: Dict[str, subprocess.Popen] = {}

    def _pid_path(self, interface: str) -> str:
        return os.path.join(self.run_dir, f"{interface}.pid")

    def _runtime_path(self, interface: str) -> str:
        return os.path.join(self.run_dir, f"{interface}.json")

    def _runtime_config(self, interface: str, config_path: str) -> dict:
        """A stored sing-box JSON as is, or the tunnel config built from a stored vless:// link."""
        with open(config_path) as f:
            content = f.read()
        if not config_path.endswith(".vless"):
            return json.loads(content)
        outbound = vless_outbound(content)
        return tun_config(outbound, interface, self._resolve(outbound["server"], outbound["server_port"]))

    def log_path(self, interface: str) -> str:
        return os.path.join(self.log_dir, f"sing-box-{interface}.log")

    def check(self, config_text: str) -> Optional[str]:
        """Runs `sing-box check` on the config text: None if it is valid, the error otherwise."""
        sing_box = self.binary_manager.get_binary_path("sing-box")
        if sing_box is None:
            return "sing-box binary not found"
        try:
            result = subprocess.run([sing_box, "check", "-c", "stdin", "--disable-color"], input=config_text,
                                    capture_output=True, text=True, timeout=CHECK_TIMEOUT_SEC, env=clean_env())
        except subprocess.TimeoutExpired:
            return f"sing-box check timed out after {CHECK_TIMEOUT_SEC}s"
        if result.returncode == 0:
            return None
        return (result.stderr or result.stdout).strip() or f"sing-box check failed (rc={result.returncode})"

    def _process_argv(self, pid: int) -> Optional[List[bytes]]:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return f.read().split(b"\0")
        except OSError:
            return None

    def pid(self, interface: str) -> Optional[int]:
        """PID of the sing-box running this tunnel, or None."""
        child = self._children.get(interface)
        if child is not None and child.poll() is not None:
            del self._children[interface]
        try:
            with open(self._pid_path(interface)) as f:
                pid = int(f.read().strip())
        except (OSError, ValueError):
            return None
        argv = self._process_argv(pid)
        # A PID left from a crash may already belong to another program.
        if not argv or os.path.basename(argv[0]) != b"sing-box":
            return None
        return pid

    def running(self) -> List[str]:
        """Interfaces of the tunnels sing-box is running now."""
        try:
            names = os.listdir(self.run_dir)
        except OSError:
            return []
        return sorted(n[:-4] for n in names if n.endswith(".pid") and self.pid(n[:-4]) is not None)

    def _log_tail(self, interface: str) -> str:
        try:
            with open(self.log_path(interface), "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - _LOG_TAIL_BYTES))
                tail = f.read().decode(errors="replace").strip()
        except OSError:
            return ""
        return tail.splitlines()[-1] if tail else ""

    def _forget(self, interface: str) -> None:
        child = self._children.pop(interface, None)
        if child is not None:
            child.poll()
        for path in (self._pid_path(interface), self._runtime_path(interface)):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def start(self, interface: str, config_path: str) -> dict:
        if self.pid(interface) is not None:
            return _result(interface)
        sing_box = self.binary_manager.get_binary_path("sing-box")
        if sing_box is None:
            return _result(interface, "sing-box binary not found")
        try:
            config = self._runtime_config(interface, config_path)
        except OSError as e:
            return _result(interface, f"Не удалось прочитать конфиг: {e}")
        except (ValueError, RecursionError) as e:
            return _result(interface, f"Не удалось собрать конфиг: {e}")
        text = json.dumps(config, indent=2, ensure_ascii=False)
        error = self.check(text)
        if error:
            return _result(interface, f"sing-box не принял конфиг: {error}")

        os.makedirs(self.run_dir, mode=0o700, exist_ok=True)
        runtime_path = self._runtime_path(interface)
        fd = os.open(runtime_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        with open(self.log_path(interface), "w") as log:
            child = subprocess.Popen([sing_box, "run", "-c", runtime_path, "--disable-color"], cwd=self.run_dir,
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                     env=clean_env(), start_new_session=True)
        self._children[interface] = child
        with open(self._pid_path(interface), "w") as f:
            f.write(str(child.pid))

        deadline = time.monotonic() + START_TIMEOUT_SEC
        while time.monotonic() < deadline:
            if child.poll() is not None:
                self._forget(interface)
                return _result(interface, f"sing-box завершился при запуске: {self._log_tail(interface) or f'rc={child.returncode}'}")
            if os.path.exists(os.path.join(self.net_dir, interface)):
                time.sleep(START_SETTLE_SEC)
                if child.poll() is not None:
                    continue
                decky.logger.info(f"Started {interface} via sing-box (pid {child.pid})")
                return _result(interface)
            time.sleep(0.2)

        tail = self._log_tail(interface)
        self.stop(interface)
        return _result(interface, f"sing-box не поднял {interface} за {START_TIMEOUT_SEC} с: {tail or 'в логе пусто'}")

    def _wait_exit(self, interface: str, pid: int, timeout: float) -> bool:
        child = self._children.get(interface)
        if child is not None and child.pid == pid:
            try:
                child.wait(timeout)
                return True
            except subprocess.TimeoutExpired:
                return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._process_argv(pid) is None:
                return True
            time.sleep(0.1)
        return False

    def stop(self, interface: str) -> dict:
        pid = self.pid(interface)
        if pid is None:
            self._forget(interface)
            return _result(interface, f"{interface} не запущен")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if not self._wait_exit(interface, pid, STOP_TIMEOUT_SEC):
            decky.logger.warning(f"{interface}: sing-box ignored SIGTERM for {STOP_TIMEOUT_SEC}s, killing it")
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self._wait_exit(interface, pid, 2)
        self._forget(interface)
        decky.logger.info(f"Stopped {interface} via sing-box")
        return _result(interface)
