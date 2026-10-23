"""Select a target before importing its hardware stack."""
import sys


HELP = """m1mu2 — memory probe workbench

Targets:
  m1mu2 ns2 --help           Switch 2 sysmodule captures and bounded reads
  m1mu2 frlg --help          FireRed Mystery Gift probe workflow

Existing `m1mu2 repl` and `m1mu2 run FILE` commands still use FireRed.
Switch reads require an already-qualified session; m1mu2 never acquires one.
"""


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"-h", "--help"}:
        print(HELP)
        return 0
    if args and args[0] in {"ns2", "switch2"}:
        from .ns2 import main as run
        return run(args[1:])
    if args and args[0] == "frlg":
        args = args[1:]
    from .cli import main as run
    return run(args)
