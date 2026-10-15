"""The vendored pokeldn host stack, imported in place. pokeldn-src/ is read-only reference: m1mu2
imports its builders and parsers and never re-implements them.

check_host_argv() is the offline half of --dry-run: it runs the host's own option parsing, run
config and build plan on an argv - exactly what bin/frlg_mg_host.py main() does before it builds a
transport - so a command line the host would refuse is refused here, with the host's own words,
without root, without a radio and without a subprocess.
"""
import contextlib
import functools
import importlib.util
import io
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POKELDN_SRC = REPO_ROOT / "pokeldn-src"
HOST_SCRIPT = POKELDN_SRC / "bin" / "frlg_mg_host.py"
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"

if str(POKELDN_SRC) not in sys.path:
    sys.path.insert(0, str(POKELDN_SRC))

from pokeldn.frlg import config as configmod  # noqa: E402
from pokeldn.frlg.rom import buffer_script as bs  # noqa: E402
from pokeldn.frlg.rom import builds  # noqa: E402

__all__ = ["REPO_ROOT", "POKELDN_SRC", "HOST_SCRIPT", "VENV_PYTHON", "bs", "builds", "configmod",
           "host_module", "HostCheck", "check_host_argv"]


@functools.cache
def host_module():
    """bin/frlg_mg_host.py as a module. Importing it defines the parser; it starts nothing."""
    spec = importlib.util.spec_from_file_location("frlg_mg_host", HOST_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class HostCheck:
    ok: bool
    message: str
    codes: tuple = ()           # the game codes the host would build a payload for


def check_host_argv(argv):
    """-> HostCheck for the host-side argv (everything after the script path). The host's main()
    up to, and not including, the transport: load the TOML config, parse, build the run config,
    plan the per-build payloads. A parser.error() comes back as ok=False with its message."""
    host = host_module()
    out, err = io.StringIO(), io.StringIO()
    argv = [str(a) for a in argv]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            file_config, shared_path, local_path = \
                host.host_cli.load_host_file_config_from_argv(argv)
            parser = host.build_parser(
                file_config, shared_path=shared_path, local_path=local_path)
            args = parser.parse_args(argv)
            if not args.live:
                parser.error("hosting only supports live mode; omit --no-live")
            config = host.build_run_config(parser, args)
            plan = host.configmod.plan_builds(
                config.payload, config.console_build, config.console_version)
    except SystemExit as exc:
        lines = [line for line in err.getvalue().splitlines() if line.strip()]
        message = lines[-1] if lines else f"host parser exited with {exc.code}"
        return HostCheck(False, message.removeprefix("-: "))
    except ValueError as exc:
        return HostCheck(False, str(exc))
    codes = tuple(getattr(plan, "codes", ()) or ())
    return HostCheck(True, "the host accepts this command line", codes)
