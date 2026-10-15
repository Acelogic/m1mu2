"""m1mu2 repl / m1mu2 run FILE.muprog: terse probe expressions -> joins -> a Session.

    m1mu2> .call GetVarPointer 0x4024
    m1mu2> .peek prev 2
    m1mu2> .peek 0x030042D0
    m1mu2> .go var4024

Dry run is the default: every join is rendered as the exact host command line, checked by the
host's own parser and journaled, and nothing is sent. --live opts in to firing, and even then every
join waits for a typed `go`; --dry-run wins over --live. A .muprog file is the same lines, one per
line; whatever is still queued at its end runs as `.go <file stem>`.

The Shell executes one line at a time and never raises: errors are printed and counted, so the
REPL keeps going and `run` stops at the first one with a nonzero exit.
"""
import argparse
import sys
from pathlib import Path

from . import pack
from .pack import PackError, prev, probe
from .policy import PolicyError
from .session import (CAPTURES_DIR, DEFAULT_BUDGET, DEFAULT_KEYS, DEFAULT_PORT, STOP_DECLINED,
                      STOP_HALTED, STOP_REFUSED, BudgetError, Session)

PROMPT = "m1mu2> "
EXIT_OK, EXIT_ERROR, EXIT_STOPPED = 0, 1, 3
SVC_OPTIONS = ("args", "hex", "in")

HELP = """\
commands (one per line; `#` starts a comment):
  .call NAME [ARG ...]       queue a call to a function the build tables name; ARGs are ints
                             (0x.. ok), and the first may be prev or prev+N
  .peek ADDR [LEN]           queue reads of LEN bytes at ADDR (1, 2, 4 or whole words; default 4);
                             ADDR may be prev or prev+N
  .svc N [N ...] [args=W,W,...] [hex=HEX] [in=r0|r1] [bkpt]
                             queue syscalls that share those operands
  .poke ADDR VALUE [WIDTH]   queue a write of WIDTH bytes (1, 2 or 4; default 4): --allow-unsafe
  .steps [STEP ...]          list the queue, or replace it with --chain-step spellings
                             (call:FlagGet,0x828  read16:prev  read32+keep:prev+0x10  svc:0x53)
  .budget [N]                show, or set, this invocation's join budget
  .go [LABEL]                compile the queue into joins and run them (dry unless --live)
  .clear                     empty the queue
  .help                      this text
  .quit | .exit              leave"""


class ShellError(ValueError):
    pass


def _number(text):
    try:
        return int(text, 0)
    except ValueError:
        raise ShellError(f"{text!r} is not a number (decimal or 0x hex)") from None


def _value(text, *, allow_prev=True):
    """An int, or `prev` / `prev+N` where the step can take the previous result."""
    head, plus, offset = text.partition("+")
    if head.strip().lower() == "prev":
        if not allow_prev:
            raise ShellError(f"{text!r}: prev is not allowed here")
        return prev + _number(offset) if plus else prev
    return _number(text)


class Shell:
    """One line in, output out. `queue` holds steps until .go; `errors` counts failed lines."""

    def __init__(self, session, *, out=print):
        self.session = session
        self.out = out
        self.queue = []
        self.errors = 0
        self.done = False
        self.commands = {
            ".call": self._call, ".peek": self._peek, ".svc": self._svc, ".poke": self._poke,
            ".steps": self._steps, ".budget": self._budget, ".go": self._go,
            ".clear": self._clear, ".help": self._help, ".quit": self._quit, ".exit": self._quit,
        }

    def execute(self, line):
        """Run one line. -> False once the shell should stop (.quit / .exit), else True."""
        words = line.split("#", 1)[0].split()
        if not words:
            return True
        command, args = words[0].lower(), words[1:]
        handler = self.commands.get(command)
        if handler is None:
            self._error(f"unknown command {words[0]!r}; .help lists them")
            return True
        try:
            handler(args)
        except (ShellError, PackError, PolicyError, BudgetError) as exc:
            self._error(str(exc))
        except Exception as exc:  # the REPL never dies on a line
            self._error(f"{type(exc).__name__}: {exc}")
        return not self.done

    def _error(self, message):
        self.errors += 1
        self.out(f"error: {message}")

    def _queue(self, steps):
        for step in steps:
            self.queue.append(step)
            self.out(f"  {len(self.queue)}. {pack.step_text(step)}")

    # -- commands ----------------------------------------------------------------------------

    def _call(self, args):
        if not args:
            raise ShellError(".call NAME [ARG ...]")
        name = args[0]
        try:
            function = int(name, 0)
        except ValueError:
            function = name
        values = [_value(a) for a in args[1:]]
        self._queue([probe.call(function, *values)])

    def _peek(self, args):
        if not 1 <= len(args) <= 2:
            raise ShellError(".peek ADDR [LEN]")
        length = _number(args[1]) if len(args) > 1 else 4
        self._queue(probe.peek(_value(args[0]), length))

    def _svc(self, args):
        numbers, options, bkpt = [], {}, False
        for arg in args:
            key, eq, value = arg.partition("=")
            if eq:
                if key.lower() not in SVC_OPTIONS:
                    raise ShellError(f"{arg!r}: .svc takes {', '.join(SVC_OPTIONS)} options")
                options[key.lower()] = value
            elif arg.lower() == "bkpt":
                bkpt = True
            else:
                numbers.append(_number(arg))
        if not numbers:
            raise ShellError(".svc N [N ...] [args=W,W,...] [hex=HEX] [in=r0|r1] [bkpt]")
        words = [_number(w) for w in options.get("args", "").split(",") if w]
        try:
            data = bytes.fromhex(options.get("hex", ""))
        except ValueError:
            raise ShellError(f"hex={options['hex']!r} is not hex bytes") from None
        data_in = options.get("in", "none")
        self._queue([probe.svc(n, *words, data=data, data_in=data_in, bkpt=bkpt)
                     for n in numbers])

    def _poke(self, args):
        if not 2 <= len(args) <= 3:
            raise ShellError(".poke ADDR VALUE [WIDTH]")
        width = _number(args[2]) if len(args) > 2 else 4
        writers = {1: probe.write8, 2: probe.write16, 4: probe.write32}
        if width not in writers:
            raise ShellError(f"a write is 1, 2 or 4 bytes, got {width}")
        self._queue([writers[width](_value(args[0]), _value(args[1]))])

    def _steps(self, args):
        if args:
            steps = [pack.parse_step(token) for token in args]
            self.queue = []
            self._queue(steps)
            return
        if not self.queue:
            self.out("(queue empty)")
        for index, step in enumerate(self.queue):
            self.out(f"  {index + 1}. {pack.step_text(step)}")

    def _budget(self, args):
        if len(args) > 1:
            raise ShellError(".budget [N]")
        if args:
            budget = _number(args[0])
            if budget < 0:
                raise ShellError("a budget is a number of joins, 0 or more")
            self.session.budget = budget
        s = self.session
        self.out(f"budget {s.budget}, {s.used} fired, {s.remaining} left")

    def _go(self, args):
        if len(args) > 1:
            raise ShellError(".go [LABEL]")
        label = args[0] if args else "probe"
        joins = pack.compile_program(self.queue, allow_unsafe=self.session.allow_unsafe,
                                     label=label)
        used = self.session.used
        try:
            results = self.session.go(joins)
        finally:
            if self.session.used > used:
                self.queue = []     # something fired: a second .go would repeat it
        if self.session.stopped == STOP_REFUSED:
            self._error("the host refused the program")
        elif results:
            self.queue = []
        elif self.session.used == used:
            self.out("nothing ran; the queue is kept")

    def _clear(self, args):
        self.queue = []
        self.out("(queue empty)")

    def _help(self, args):
        self.out(HELP)

    def _quit(self, args):
        if self.queue:
            self.out(f"leaving {len(self.queue)} queued step(s) unrun")
        self.done = True


def _parser():
    common = argparse.ArgumentParser(add_help=False)
    mode = common.add_argument_group("mode")
    mode.add_argument("--dry-run", action="store_true",
                      help="render, check and journal only (the default; wins over --live)")
    mode.add_argument("--live", action="store_true",
                      help="fire joins over the radio, each after a typed `go`")
    common.add_argument("--allow-unsafe", action="store_true",
                        help="let out steps policy.py gates (writes, ungated syscalls, ...)")
    common.add_argument("--budget", type=int, default=DEFAULT_BUDGET, metavar="N",
                        help="live joins this invocation may fire, health pairs included "
                             "(default %(default)s)")
    common.add_argument("--keys", type=Path, default=DEFAULT_KEYS, metavar="PATH",
                        help="prod.keys for the host (default keys/prod.keys)")
    common.add_argument("--port", default=DEFAULT_PORT, metavar="P",
                        help="the ESP32 radio's serial port (default %(default)s)")
    common.add_argument("--mac", default=None, metavar="MAC",
                        help="the radio's MAC from `esptool read_mac`, for the journal")
    common.add_argument("--captures", type=Path, default=CAPTURES_DIR, metavar="DIR",
                        help="where logs and dumps land (default captures/m1mu2)")
    common.add_argument("--journal", type=Path, default=None, metavar="PATH",
                        help="the JSONL journal (default <captures>/journal.jsonl)")
    parser = argparse.ArgumentParser(prog="m1mu2", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("repl", parents=[common], help="interactive probe shell")
    run = sub.add_parser("run", parents=[common], help="execute a .muprog file")
    run.add_argument("file", type=Path, metavar="FILE.muprog")
    return parser


def _banner(session):
    if session.live:
        return (f"m1mu2 LIVE: budget {session.budget} join(s); every join waits for a typed "
                f"`go`. Port {session.port}, captures in {session.captures_dir}")
    return ("m1mu2 dry run: joins are rendered, checked by the host's parser and journaled; "
            "nothing is sent")


def _stop_code(session):
    if session.stopped in (STOP_DECLINED, STOP_HALTED):
        return EXIT_STOPPED
    if session.stopped == STOP_REFUSED:
        return EXIT_ERROR
    return None


def repl(shell):
    if sys.stdin.isatty():
        try:
            import readline  # noqa: F401  (line editing and history for input())
        except ImportError:
            pass
    shell.out(".help lists the commands")
    while True:
        try:
            line = input(PROMPT)
        except EOFError:
            shell.out("")
            break
        except KeyboardInterrupt:
            shell.out("")
            continue
        if not shell.execute(line):
            break
    return EXIT_OK


def run_file(shell, path):
    """Execute a .muprog: stop at the first error (exit 1), decline or halt (exit 3)."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        shell.out(f"error: cannot read {path}: {exc}")
        return EXIT_ERROR
    for number, line in enumerate(lines, 1):
        if not line.split("#", 1)[0].strip():
            continue
        shell.out(f"{PROMPT}{line.strip()}")
        errors = shell.errors
        if not shell.execute(line):
            return EXIT_OK
        if shell.errors > errors:
            shell.out(f"stopped at {path}:{number}")
            return EXIT_ERROR
        stop = _stop_code(shell.session)
        if stop is not None:
            return stop
    if shell.queue:
        label = Path(path).stem
        shell.out(f"{PROMPT}.go {label}  # end of file")
        errors = shell.errors
        shell.execute(f".go {label}")
        if shell.errors > errors:
            return EXIT_ERROR
        stop = _stop_code(shell.session)
        if stop is not None:
            return stop
    return EXIT_OK


def main(argv=None, *, journal_factory=None, **session_kwargs):
    """-> exit status. `journal_factory(path)` and `session_kwargs` (runner, confirm,
    load_outcome, ...) are injection points for tests; the command line never sets them."""
    args = _parser().parse_args(argv)
    journal = args.journal
    if journal_factory is not None:
        journal = journal_factory(journal or Path(args.captures) / "journal.jsonl")
    session_kwargs.setdefault("out", print)
    session = Session(budget=args.budget, allow_unsafe=args.allow_unsafe,
                      live=args.live and not args.dry_run, keys=args.keys, port=args.port,
                      captures_dir=args.captures, journal=journal, radio_mac=args.mac,
                      **session_kwargs)
    shell = Shell(session, out=session.out)
    shell.out(_banner(session))
    if args.command == "repl":
        return repl(shell)
    return run_file(shell, args.file)


if __name__ == "__main__":
    raise SystemExit(main())
