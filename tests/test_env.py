"""The live path's imports, offline. check_host_argv and every other test stop before the
transport, so a venv missing the radio stack's dependencies stays green and fails only after the
operator types `go` (2026-10-15: python-netlink and zstandard were missing; ldn_scan.py died on
`import netlink`)."""
import importlib

import pytest

from m1mu2.upstream import POKELDN_SRC

# bin/frlg_mg_host.py and tools/ldn/ldn_scan.py put the bundled LDN first on sys.path the same way.
BUNDLED_LDN = POKELDN_SRC / "vendor" / "LDN"


@pytest.mark.parametrize("module", [
    "netlink",                  # python-netlink, pinned by vendor/LDN/setup.py; ldn.wlan imports it
    "zstandard",                # Pia messages are zstd [pokeldn/ldn/crypto.py], which only warns
    "ldn",                      # what ldn_scan.py imports
    "pokeldn.ldn.esp32_wlan",   # ldn.wlan backed by the ESP32 radio
])
def test_live_path_imports(module, monkeypatch):
    monkeypatch.syspath_prepend(str(BUNDLED_LDN))
    importlib.import_module(module)
