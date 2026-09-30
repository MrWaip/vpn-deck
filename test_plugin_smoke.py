#!/usr/bin/env python3
"""
Smoke test for Plugin class — verifies all public RPC methods without real binaries.
"""

import asyncio
import base64
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Mock: decky
# ---------------------------------------------------------------------------

class _MockLogger:
    def info(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg): pass
    def debug(self, msg): pass


class _MockDecky:
    logger = _MockLogger()
    DECKY_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
    DECKY_PLUGIN_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    plugin_home = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".test_home")


sys.modules["decky"] = _MockDecky()

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_modules"))
from vpn_deck import network_watch as _network_watch  # noqa: E402  real watcher, managers are mocked below

# ---------------------------------------------------------------------------
# Mock: vpn_deck managers
# ---------------------------------------------------------------------------

class _MockBinaryManager:
    binary_names = ["amneziawg-go", "awg", "awg-quick"]

    def get_binaries_info(self):
        return {name: {"path": None, "version": None} for name in self.binary_names}

    def detect_binaries(self):
        return {name: None for name in self.binary_names}

    def get_binary_path(self, name):
        return None

    def invalidate_cache(self):
        pass


class _MockConfigManager:
    def __init__(self):
        self.written = []

    def write_config(self, name, content):
        self.written.append((name, content))
        return {"success": True, "config_name": name, "interface_name": f"awg-{name}", "error": None}

    async def list_all_configs(self):
        return [{"name": "test", "interface": "awg-test", "managed_by": "vpn-deck"}]

    async def scan_existing_configs(self):
        return {"managed": [], "existing": []}

    def get_interface_name(self, config_name):
        if not config_name:
            raise ValueError("config_name is empty")
        return f"awg-{config_name}"

    async def delete_config(self, name):
        return {"success": True, "config_name": name, "error": ""}

    async def get_config_content(self, name):
        return None

    async def validate_config(self, content):
        return {"valid": True, "errors": [], "warnings": [], "info": {}}


class _MockServiceManager:
    def __init__(self, bm):
        self.binary_manager = bm
        self.lock = threading.RLock()

    def start_interface(self, interface):
        return {"success": True, "error": None}

    def stop_interface(self, interface):
        return {"success": True, "error": None}

    def get_status(self, interface):
        return {"status": "inactive", "error": None}

    def get_all_statuses(self):
        return []

    def stop_all_interfaces(self, only_managed=False):
        return {"success": True, "stopped": [], "error": None}


class _MockDiagnostics:
    def check(self, targets=None):
        return []


_spec = importlib.util.spec_from_file_location(
    "vpn_deck_vpn_uri",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_modules", "vpn_deck", "vpn_uri.py"),
)
_vpn_uri = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vpn_uri)


class _MockVpnDeck:
    BinaryManager = _MockBinaryManager
    ConfigManager = _MockConfigManager
    Diagnostics = _MockDiagnostics
    NetworkWatch = _network_watch.NetworkWatch
    ServiceManager = _MockServiceManager
    # The mock is used as an instance, so plain functions would turn into bound methods.
    VpnUriError = _vpn_uri.VpnUriError
    decode_vpn_uri = staticmethod(_vpn_uri.decode_vpn_uri)
    is_vpn_uri = staticmethod(_vpn_uri.is_vpn_uri)
    looks_like_wg_config = staticmethod(_vpn_uri.looks_like_wg_config)


sys.modules["vpn_deck"] = _MockVpnDeck()

# ---------------------------------------------------------------------------
# Import Plugin (after mocks are in place)
# ---------------------------------------------------------------------------

from main import Plugin  # noqa: E402

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f"  PASS  {name}")


def fail(name, reason):
    global FAIL
    FAIL += 1
    print(f"  FAIL  {name}: {reason}")


def assert_dict(result, name):
    if isinstance(result, dict):
        ok(name)
    else:
        fail(name, f"expected dict, got {type(result).__name__}: {result!r}")


def assert_list(result, name):
    if isinstance(result, list):
        ok(name)
    else:
        fail(name, f"expected list, got {type(result).__name__}: {result!r}")


def assert_bool(result, name):
    if isinstance(result, bool):
        ok(name)
    else:
        fail(name, f"expected bool, got {type(result).__name__}: {result!r}")


def assert_success_false(result, name):
    if isinstance(result, dict) and result.get("success") is False and result.get("error"):
        ok(name)
    else:
        fail(name, f"expected {{success: False, error: ...}}, got {result!r}")


NATIVE_CONFIG = """[Interface]
Address = 10.8.1.2/32
DNS = 1.1.1.1, 1.0.0.1
PrivateKey = YAnz5TF+lXXJte14tji3zlMNftft3UL32bbjzVEwPBs=
Jc = 4

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:46907
"""


def make_vpn_link(config_template, dns1, dns2):
    last_config = json.dumps({"config": config_template})
    data = {
        "containers": [{"container": "amnezia-awg", "awg": {"last_config": last_config}}],
        "defaultContainer": "amnezia-awg",
        "dns1": dns1,
        "dns2": dns2,
    }
    raw = json.dumps(data).encode()
    raw = struct.pack(">I", len(raw)) + zlib.compress(raw)
    return "vpn://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


async def import_file(plugin, tmpdir, filename, data: bytes):
    path = os.path.join(tmpdir, filename)
    with open(path, "wb") as f:
        f.write(data)
    plugin.config_manager.written.clear()
    result = await plugin.import_vpn_config("imported", path=path)
    return result, list(plugin.config_manager.written)


def assert_imported(result, written, expected_content, name):
    if not (isinstance(result, dict) and result.get("success") is True):
        fail(name, f"expected success, got {result!r}")
    elif [n for n, _ in written] != ["imported"]:
        fail(name, f"expected one write_config('imported', ...), got {written!r}")
    elif written[0][1] != expected_content:
        fail(name, f"unexpected written content: {written[0][1]!r}")
    else:
        ok(name)


def assert_rejected(result, written, error_prefix, name):
    if not (isinstance(result, dict) and result.get("success") is False
            and str(result.get("error", "")).startswith(error_prefix)):
        fail(name, f"expected error starting with {error_prefix!r}, got {result!r}")
    elif written:
        fail(name, f"nothing must be written on error, got {written!r}")
    else:
        ok(name)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def run_tests():
    plugin = Plugin()

    print("\n[vpn methods]")
    assert_list(await plugin.vpn_status_all(), "vpn_status_all()")
    assert_dict(await plugin.vpn_stop_all(), "vpn_stop_all()")

    print("\n[config list]")
    assert_list(await plugin.list_configs_with_status(), "list_configs_with_status()")

    print("\n[vpn_start_config / vpn_stop_config — normal]")
    assert_dict(await plugin.vpn_start_config("myconf"), "vpn_start_config('myconf')")
    assert_dict(await plugin.vpn_stop_config("myconf"), "vpn_stop_config('myconf')")

    print("\n[REGRESSION: dict coercion]")
    r = await plugin.vpn_start_config({"config_name": "myconf"})
    assert_dict(r, "vpn_start_config({config_name: 'myconf'}) returns dict")
    if isinstance(r, dict) and r.get("success") is True:
        ok("vpn_start_config dict-coercion → success")
    else:
        fail("vpn_start_config dict-coercion → success", f"got {r!r}")

    r = await plugin.vpn_stop_config({"config_name": "myconf"})
    assert_dict(r, "vpn_stop_config({config_name: 'myconf'}) returns dict")
    if isinstance(r, dict) and r.get("success") is True:
        ok("vpn_stop_config dict-coercion → success")
    else:
        fail("vpn_stop_config dict-coercion → success", f"got {r!r}")

    print("\n[REGRESSION: empty config_name]")
    assert_success_false(await plugin.vpn_start_config(""), "vpn_start_config('')")
    assert_success_false(await plugin.vpn_stop_config(""), "vpn_stop_config('')")

    print("\n[REGRESSION: dict with empty config_name]")
    assert_success_false(await plugin.vpn_start_config({"config_name": ""}), "vpn_start_config({config_name: ''})")
    assert_success_false(await plugin.vpn_stop_config({"config_name": ""}), "vpn_stop_config({config_name: ''})")

    print("\n[errors API]")
    assert_list(await plugin.get_errors(), "get_errors()")
    assert_bool(await plugin.clear_errors(), "clear_errors()")

    print("\n[binaries]")
    assert_dict(await plugin.get_binaries_info(), "get_binaries_info()")
    assert_dict(await plugin.check_binaries(), "check_binaries()")

    print("\n[config manager API]")
    assert_list(await plugin.list_all_configs(), "list_all_configs()")
    assert_dict(await plugin.scan_existing_configs(), "scan_existing_configs()")
    assert_dict(await plugin.import_vpn_config("test", path="/nonexistent/file.conf"), "import_vpn_config (missing file)")
    assert_dict(await plugin.delete_vpn_config("test"), "delete_vpn_config('test')")
    # get_vpn_config returns None or str — just no exception
    try:
        await plugin.get_vpn_config("test")
        ok("get_vpn_config('test') no exception")
    except Exception as e:
        fail("get_vpn_config('test')", str(e))

    print("\n[diagnostics]")
    assert_list(await plugin.diagnose_connectivity(), "diagnose_connectivity()")

    print("\n[import_vpn_config: file formats]")
    tmpdir = tempfile.mkdtemp(prefix="vpn-deck-smoke-")
    try:
        r, w = await import_file(plugin, tmpdir, "native.conf", NATIVE_CONFIG.encode())
        assert_imported(r, w, NATIVE_CONFIG, "native .conf imported as is")

        r, w = await import_file(plugin, tmpdir, "bom.conf", b"\xef\xbb\xbf" + NATIVE_CONFIG.encode())
        assert_imported(r, w, NATIVE_CONFIG, ".conf with UTF-8 BOM imported without the BOM")

        template = NATIVE_CONFIG.replace("DNS = 1.1.1.1, 1.0.0.1", "DNS = $PRIMARY_DNS, $SECONDARY_DNS")
        expected = NATIVE_CONFIG.replace("DNS = 1.1.1.1, 1.0.0.1", "DNS = 172.29.172.254, 9.9.9.9")
        link = make_vpn_link(template, "172.29.172.254", "9.9.9.9")
        r, w = await import_file(plugin, tmpdir, "link.txt", (link + "\n").encode())
        assert_imported(r, w, expected, "vpn:// link in .txt written as decoded config with DNS")

        r, w = await import_file(plugin, tmpdir, "link-win.txt", ("\ufeff" + link + "\r\n").encode())
        assert_imported(r, w, expected, "vpn:// link with BOM and CRLF written as decoded config")

        r, w = await import_file(plugin, tmpdir, "broken.txt", b"vpn://this-is-not-base64!!!\n")
        assert_rejected(r, w, "Не удалось разобрать ссылку vpn://:", "broken vpn:// link rejected, nothing written")

        no_peer_link = make_vpn_link(NATIVE_CONFIG.split("[Peer]")[0], "1.1.1.1", "1.0.0.1")
        r, w = await import_file(plugin, tmpdir, "no-peer.txt", no_peer_link.encode())
        assert_rejected(r, w, "Не удалось разобрать ссылку vpn://:", "vpn:// link without [Peer] rejected, nothing written")

        r, w = await import_file(plugin, tmpdir, "notes.txt", b"just some notes\nnothing to see here\n")
        assert_rejected(r, w, "Файл не похож на конфиг", "random text rejected, nothing written")

        r, w = await import_file(plugin, tmpdir, "image.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe\xfd")
        assert_rejected(r, w, "Файл не текстовый", "binary file rejected, nothing written")

        r, w = await import_file(plugin, tmpdir, "huge.conf", NATIVE_CONFIG.encode() + b"#" * (1024 * 1024))
        assert_rejected(r, w, "Файл больше 1 МБ", "file over 1 MB rejected, nothing written")

        r, w = await import_file(plugin, tmpdir, "empty.conf", b" \n\n")
        assert_rejected(r, w, "Файл пустой", "empty file rejected, nothing written")

        plugin.config_manager.written.clear()
        r = await plugin.import_vpn_config("imported", path=os.path.join(tmpdir, "missing.conf"))
        assert_rejected(r, plugin.config_manager.written, "Файл не найден", "missing file rejected, nothing written")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\n[_rpc decorator: exception → dict]")
    # Force an exception by passing a bad arg that gets past coercion
    orig = plugin.config_manager.get_interface_name
    def boom(name): raise RuntimeError("forced error")
    plugin.config_manager.get_interface_name = boom
    r = await plugin.vpn_start_config("anyname")
    plugin.config_manager.get_interface_name = orig
    assert_success_false(r, "_rpc catches exception → {success: False, error: ...}")

    print("\n[network watch lifecycle]")
    def no_subprocess(*args, **kwargs):
        raise AssertionError(f"subprocess.run called: {args!r}")

    logged, ticks = [], []
    real_run, real_error, interval = subprocess.run, _MockLogger.error, _network_watch.CHECK_INTERVAL_SEC
    subprocess.run = no_subprocess
    _MockLogger.error = lambda self, msg: logged.append(msg)
    _network_watch.CHECK_INTERVAL_SEC = 0.01
    try:
        p = Plugin()
        p.binary_manager.get_binary_path = lambda name: ticks.append(name)
        await p._main()
        task = p.network_watch._task
        await p._main()
        started_once = task is not None and p.network_watch._task is task
        await asyncio.sleep(0.05)
        running = task is not None and not task.done()
        await p._unload()
        stopped = task is not None and task.cancelled() and p.network_watch._task is None
    finally:
        subprocess.run, _MockLogger.error = real_run, real_error
        _network_watch.CHECK_INTERVAL_SEC = interval
    watch_errors = [m for m in logged if "Network watch" in m or "AssertionError" in m]
    if started_once and running and ticks and stopped and not watch_errors:
        ok("_main starts one watcher, it ticks, _unload stops it")
    else:
        fail("network watch lifecycle",
             f"started_once={started_once} running={running} ticks={len(ticks)} stopped={stopped} errors={watch_errors}")


async def main():
    print("=" * 60)
    print("Plugin Smoke Test")
    print("=" * 60)

    try:
        await run_tests()
    except Exception as e:
        import traceback
        print(f"\nUNHANDLED EXCEPTION: {e}")
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 60)
    if FAIL == 0:
        print(f"ALL {PASS} TESTS PASSED")
    else:
        print(f"{PASS} passed, {FAIL} FAILED")
    print("=" * 60)

    if FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
