"""Python steps -> join programs -> the buffer-script half of a frlg_mg_host.py command line.

    from m1mu2.pack import probe, prev, compile_program
    joins = compile_program([probe.call("GetVarPointer", 0x4024), probe.read16(prev),
                             probe.read32(0x030042D0)], label="var4024")
    joins[0].host_args()
    # ['--buffer-script', 'call-chain', '--chain-step', 'call:GetVarPointer,0x4024',
    #  '--chain-step', 'read16:prev', '--chain-step', 'read32:0x30042D0']

One join carries ONE buffer script, and the two that take steps are different payloads
[asm/sloop-svc.s, asm/call-chain.s]:

- sloop-svc: up to bs.SLOOP_MAX_CALLS (8) syscalls sharing one r0..r3 and one data buffer, all
  swi or all bkpt (--svc-bkpt flips the single thunk). No `prev`.
- call-chain: up to bs.CHAIN_MAX_STEPS (16) calls, reads and writes; `prev` / `prev+N` carries the
  previous step's result into a target or a first argument.

compile_program() splits a step list into joins at every change of payload, of shared syscall
operands, or at the size limit. `prev` does not survive a join boundary, so a split that would
need it is refused. Steps are upstream's own bs.ChainStep; every join is built with upstream's
builder before it is accepted, so the host's guards run on top of policy.py's.
"""
from dataclasses import dataclass

from . import policy
from .upstream import bs, builds

SVC_DATA_IN = {"none": 0, "r0": bs.SLOOP_R0_IS_DATA, "r1": bs.SLOOP_R1_IS_DATA}
SCRIPTS = (bs.SLOOP_SVC, bs.CALL_CHAIN)


class PackError(ValueError):
    pass


def _word(value):
    return int(value) & 0xFFFFFFFF


def hex_word(value):
    """The one spelling of a number on the host command line."""
    return f"0x{_word(value):X}"


@dataclass(frozen=True)
class PrevRef:
    """`prev` in a step: the previous step's result, plus `offset` bytes."""
    offset: int = 0

    def __add__(self, other):
        return PrevRef(_word(self.offset + int(other)))

    __radd__ = __add__

    def __repr__(self):
        return "prev" if not self.offset else f"prev+{hex_word(self.offset)}"


prev = PrevRef()


@dataclass(frozen=True)
class SvcStep:
    """One Sloop syscall. Consecutive SvcSteps share a join only when `operands` match: the
    payload has one r0..r3, one data buffer and one thunk mode for all of its calls."""
    number: int
    args: tuple = ()
    data: bytes = b""
    data_in: str = "none"
    bkpt: bool = False

    @property
    def operands(self):
        return (self.args, self.data, self.data_in, self.bkpt)

    def describe(self):
        mode = "bkpt" if self.bkpt else "swi"
        regs = ", ".join(hex_word(a) for a in self.args)
        data = f" data={self.data.hex()} in {self.data_in}" if self.data else ""
        return f"{mode} 0x{self.number:02X}({regs}){data}"


def _target(value):
    """-> (target, from_prev) from an int or a PrevRef."""
    if isinstance(value, PrevRef):
        return value.offset, True
    return _word(value), False


class _Probe:
    """Step constructors. Each returns one step; a program is a list of them."""

    def call(self, function, *args, keep=False):
        if isinstance(function, PrevRef):
            raise PackError("a call to a computed address cannot be checked from here; name the "
                            "function")
        name = None
        if isinstance(function, str):
            name = policy.canonical_callee(function)
            if name is None:
                raise PackError(f"{function!r} is not a function the build tables name; known: "
                                + ", ".join(sorted(builds.DEFAULT.callable)))
            target = builds.DEFAULT.callable_function(name)
        else:
            target = _word(function)
        words, arg_from_prev = [], False
        for index, arg in enumerate(args):
            if isinstance(arg, PrevRef):
                if index:
                    raise PackError("only the FIRST argument can be prev - the payload carries "
                                    "one previous result, not a register file")
                arg_from_prev = True
                words.append(arg.offset)
            else:
                words.append(_word(arg))
        return bs.ChainStep(bs.CHAIN_CALL, target, tuple(words), arg_from_prev=arg_from_prev,
                            keep_prev=bool(keep), function_name=name)

    def _read(self, size, address, keep):
        target, from_prev = _target(address)
        step = bs.chain_read(target, size, from_prev=from_prev, keep_prev=keep)
        return step

    def read32(self, address, *, keep=False):
        return self._read(4, address, keep)

    def read16(self, address, *, keep=False):
        return self._read(2, address, keep)

    def read8(self, address, *, keep=False):
        return self._read(1, address, keep)

    def _write(self, size, address, value):
        target, from_prev = _target(address)
        value, value_from_prev = _target(value)
        return bs.chain_write(target, value, size, from_prev=from_prev,
                              value_from_prev=value_from_prev)

    def write32(self, address, value):
        return self._write(4, address, value)

    def write16(self, address, value):
        return self._write(2, address, value)

    def write8(self, address, value):
        return self._write(1, address, value)

    def svc(self, number, *args, data=b"", data_in="none", bkpt=False):
        if data_in not in SVC_DATA_IN:
            raise PackError(f"data_in is one of {', '.join(SVC_DATA_IN)}, got {data_in!r}")
        if isinstance(data, str):
            data = data.encode("utf-8")
        return SvcStep(int(number), tuple(_word(a) for a in args), bytes(data), data_in,
                       bool(bkpt))

    def peek(self, address, length=4):
        """`length` bytes at `address` as reads: one read of 1, 2 or 4 bytes, or whole words.
        Only the first read may be prev-relative and the rest keep prev, so prev+N stays put."""
        length = int(length)
        if length in (1, 2, 4):
            return [self._read(length, address, False)]
        if length <= 0 or length % 4:
            raise PackError(f"a peek is 1, 2 or 4 bytes or a whole number of words, got {length}")
        base, from_prev = _target(address)
        return [bs.chain_read(_word(base + 4 * i), 4, from_prev=from_prev, keep_prev=from_prev)
                for i in range(length // 4)]


probe = _Probe()


def chain_step_text(step):
    """-> the --chain-step spelling upstream's parse_chain_step reads back to an equal step."""
    op = bs.CHAIN_OP_NAMES[int(step.op) & 0xFF] + ("+keep" if step.keep_prev else "")
    if step.target_from_prev:
        target = "prev" if not step.target else f"prev+{hex_word(step.target)}"
    elif step.op == bs.CHAIN_CALL and step.function_name:
        target = policy.canonical_callee(step.function_name) or step.function_name
    else:
        target = hex_word(step.target)
    fields = [target]
    for index, arg in enumerate(step.args):
        if index == 0 and step.arg_from_prev:
            fields.append("prev" if not arg else f"prev+{hex_word(arg)}")
        else:
            fields.append(hex_word(arg))
    return f"{op}:{','.join(fields)}"


def step_text(step):
    """A step as one line, for logs, journals and the REPL."""
    return step.describe() if isinstance(step, SvcStep) else chain_step_text(step)


def _uses_prev(step):
    return isinstance(step, bs.ChainStep) and (step.target_from_prev or step.arg_from_prev)


@dataclass(frozen=True)
class Join:
    """One session: one buffer script, its steps, and what policy said about them."""
    script: str
    steps: tuple
    label: str = ""
    assessment: policy.Assessment = policy.Assessment()

    @property
    def unsafe(self):
        """Did a step need --allow-unsafe?"""
        return bool(self.assessment.unsafe)

    @property
    def risky(self):
        return bool(self.assessment.risky)

    @property
    def host_write_unsafe(self):
        """Does the HOST need --write-unsafe for this? Not the same question as `unsafe`: the
        host passes named calls freely, and m1mu2 asks for an override on more syscalls."""
        if self.script == bs.CALL_CHAIN:
            return any(int(s.op) & 0xFF in bs.CHAIN_WRITES for s in self.steps)
        data_in, bkpt = self.steps[0].data_in, self.steps[0].bkpt
        return bkpt or any(
            n not in bs.SLOOP_SAFE_NUMBERS
            or (n == bs.SWI_BAD_WORD_CHECK and data_in != "r0") for n in self.numbers)

    @property
    def numbers(self):
        return tuple(s.number for s in self.steps) if self.script == bs.SLOOP_SVC else ()

    def host_args(self):
        """The buffer-script options, in the order the host's --help lists them."""
        argv = ["--buffer-script", self.script]
        if self.script == bs.CALL_CHAIN:
            for step in self.steps:
                argv += ["--chain-step", chain_step_text(step)]
        else:
            args, data, data_in, bkpt = self.steps[0].operands
            for number in self.numbers:
                argv += ["--svc-number", f"0x{number:02X}"]
            for word in args:
                argv += ["--svc-arg", hex_word(word)]
            if data:
                argv += ["--svc-hex", data.hex()]
            if bkpt:
                argv += ["--svc-bkpt"]
            if data_in != "none":
                argv += ["--svc-data-in", data_in]
        if self.host_write_unsafe:
            argv += ["--write-unsafe"]
        return argv

    def build_code(self, build=None):
        """The payload bytes upstream would send to `build` - the host's own guards, offline."""
        unsafe = self.host_write_unsafe
        if self.script == bs.CALL_CHAIN:
            return bs.build_call_chain(self.steps, unsafe=unsafe, build=build)
        args, data, data_in, bkpt = self.steps[0].operands
        return bs.build_sloop_svc(list(self.numbers), args, data, flags=SVC_DATA_IN[data_in],
                                  unsafe=unsafe, bkpt=bkpt)

    def answer_size(self):
        if self.script == bs.CALL_CHAIN:
            return bs.CHAIN_ANSWER_SIZE
        return bs.sloop_svc_answer_size(len(self.steps[0].data))

    def describe(self):
        head = f"{self.label or 'join'}: {self.script}, {len(self.steps)} step(s)"
        flags = [f for f, on in (("UNSAFE", self.unsafe), ("risky", self.risky)) if on]
        lines = [head + (f" [{', '.join(flags)}]" if flags else "")]
        lines += [f"  {i + 1}. {step_text(s)}" for i, s in enumerate(self.steps)]
        lines += [f"  ! {reason}" for reason in self.assessment.risky]
        return lines


def health_join(label="health"):
    """The verification readers that follow a risky join."""
    return compile_program([probe.svc(n) for n in policy.HEALTH_PAIR], label=label)[0]


def _flatten(steps):
    for step in steps:
        if isinstance(step, (list, tuple)):
            yield from _flatten(step)
        else:
            yield step


def _groups(steps):
    """Split into (script, steps) runs a single payload can carry."""
    runs = []
    for step in steps:
        if isinstance(step, SvcStep):
            script, limit = bs.SLOOP_SVC, bs.SLOOP_MAX_CALLS
        elif isinstance(step, bs.ChainStep):
            script, limit = bs.CALL_CHAIN, bs.CHAIN_MAX_STEPS
        else:
            raise PackError(f"{step!r} is not a step; build steps with m1mu2.pack.probe")
        if runs:
            last_script, last = runs[-1]
            same = last_script == script and len(last) < limit and (
                script == bs.CALL_CHAIN or last[0].operands == step.operands)
            if same:
                last.append(step)
                continue
        if _uses_prev(step):
            where = ("is the first step, so there is no previous result" if not runs else
                     "starts a new join (a new payload, or past the step limit) and prev does "
                     "not survive a join boundary")
            raise PackError(f"{chain_step_text(step)} uses prev, but it {where}")
        runs.append((script, [step]))
    return runs


def compile_program(steps, *, allow_unsafe=False, label=""):
    """-> tuple of Join, in order. Raises PackError (or policy.PolicyError) for anything the
    operator did not explicitly allow or the host would refuse."""
    steps = list(_flatten(steps))
    if not steps:
        raise PackError("a program needs at least one step")
    runs = _groups(steps)
    joins = []
    for index, (script, run) in enumerate(runs):
        if script == bs.SLOOP_SVC:
            assessment = policy.Assessment()
            for step in run:
                assessment += policy.assess_svc(step.number, data_in=step.data_in,
                                                bkpt=step.bkpt)
        else:
            assessment = policy.assess_chain(run)
        if assessment.unsafe and not allow_unsafe:
            raise policy.PolicyError(
                "needs --allow-unsafe:\n" + "\n".join(f"  - {r}" for r in assessment.unsafe))
        name = label if len(runs) == 1 or not label else f"{label}-{index + 1}"
        join = Join(script, tuple(run), name, assessment)
        try:
            join.build_code()
        except bs.BufferScriptError as exc:
            raise PackError(f"{name or script}: the host's builder refuses it: {exc}") from None
        joins.append(join)
    return tuple(joins)


def parse_step(text):
    """-> one step from its command-line spelling: a --chain-step (`read16:prev`,
    `call:FlagGet,0x828`) via upstream's parse_chain_step, or `svc:0x53`."""
    text = str(text).strip()
    head, _, rest = text.partition(":")
    if head.strip().lower() in ("svc", "bkpt"):
        try:
            return probe.svc(int(rest, 0), bkpt=head.strip().lower() == "bkpt")
        except ValueError:
            raise PackError(f"{text!r}: svc takes one number, e.g. svc:0x53") from None
    try:
        step = bs.parse_chain_step(text, resolve=_resolve_name)
    except bs.BufferScriptError as exc:
        raise PackError(str(exc)) from None
    if step.function_name is not None:
        step = bs.ChainStep(step.op, step.target, step.args, step.target_from_prev,
                            step.arg_from_prev, step.keep_prev,
                            policy.canonical_callee(step.function_name))
    return step


def _resolve_name(name):
    canonical = policy.canonical_callee(name)
    if canonical is None:
        raise KeyError(name)
    return builds.DEFAULT.callable_function(canonical)


def join_from_host_args(argv, *, label=""):
    """-> the Join a buffer-script argv carries: the inverse of Join.host_args(), for the journal,
    replay and the golden tests. Policy is assessed but not enforced: the argv already ran or was
    already allowed."""
    argv = [str(a) for a in argv]
    script, steps = None, []
    svc = {"numbers": [], "args": [], "data": b"", "data_in": "none", "bkpt": False}
    index = 0
    while index < len(argv):
        flag = argv[index]
        value = argv[index + 1] if index + 1 < len(argv) else None
        takes = flag in ("--buffer-script", "--chain-step", "--svc-number", "--svc-arg",
                         "--svc-hex", "--svc-text", "--svc-data-in")
        if takes and value is None:
            raise PackError(f"{flag} needs a value")
        if flag == "--buffer-script":
            script = value
        elif flag == "--chain-step":
            steps.append(parse_step(value))
        elif flag == "--svc-number":
            svc["numbers"].append(int(value, 0))
        elif flag == "--svc-arg":
            svc["args"].append(_word(int(value, 0)))
        elif flag == "--svc-hex":
            svc["data"] = bytes.fromhex(value.replace(" ", ""))
        elif flag == "--svc-text":
            svc["data"] = value.encode("utf-8")
        elif flag == "--svc-data-in":
            svc["data_in"] = value
        elif flag == "--svc-bkpt":
            svc["bkpt"] = True
        index += 2 if takes else 1
    if script == bs.SLOOP_SVC:
        steps = [probe.svc(n, *svc["args"], data=svc["data"], data_in=svc["data_in"],
                           bkpt=svc["bkpt"]) for n in svc["numbers"]]
    elif script != bs.CALL_CHAIN:
        raise PackError(f"m1mu2 composes {' and '.join(SCRIPTS)}, not {script!r}")
    joins = compile_program(steps, allow_unsafe=True, label=label)
    if len(joins) != 1:
        raise PackError(f"that argv is {len(joins)} joins, not one")
    return joins[0]
