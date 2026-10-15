"""Register the poke-m1n1 `smoke` agent as a shipped buffer script (idempotent).

Same house style as scripts/register-proxy-stub.py: read scratchpad/smoke_agent.py
fresh, assemble deterministically (Keystone + strict capstone gate), then inject:

  pokeldn/frlg/rom/buffer_payloads.py   PAYLOADS['smoke']        (bytes + src sha)
  pokeldn/frlg/rom/buffer_script.py     SMOKE name, build_smoke(), spec, DUMP_SCRIPTS
  pokeldn/frlg/config.py                smoke_* payload fields, validation, build branch
  bin/frlg_mg_host.py                   --smoke-* flags wired to the payload

Stage knob = --dump-blocks N (the shipped multi-triple client script); every phase
answers a constant 0x140-byte slab frame. Run under .venv-pokeldn from repo root.
"""
import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scratchpad"))
_spec = importlib.util.spec_from_file_location("smoke_agent", ROOT / "scratchpad" / "smoke_agent.py")
SA = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SA)

CODE, SRC = SA.assemble()
SRC_SHA = hashlib.sha256(SRC.encode()).hexdigest()
PARAM_OFF = SA.param_offset(CODE)
assert len(CODE) <= 0x400 and len(CODE) % 4 == 0
# sanity: patched params must round-trip through the shipped-bytes view
_probe = SA.patch(CODE, nonce=0xAABBCCDD, dump_src=1, dump_len=4, poke_addr=8, poke_val=9)
assert _probe[PARAM_OFF:PARAM_OFF + 20] == bytes([0xdd, 0xcc, 0xbb, 0xaa, 1, 0, 0, 0,
                                                  4, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0])

BS = ROOT / "pokeldn/frlg/rom/buffer_script.py"
BP = ROOT / "pokeldn/frlg/rom/buffer_payloads.py"
CFG = ROOT / "pokeldn/frlg/config.py"
HOST = ROOT / "bin/frlg_mg_host.py"


def sub_once(path, old, new, label):
    text = path.read_text(encoding="utf-8")
    if new in text:
        print(f"   = {path.name}: {label} present")
        return
    if text.count(old) != 1:
        raise SystemExit(f"x {path.name} [{label}]: anchor count "
                         f"{text.count(old)}, refusing")
    path.write_text(text.replace(old, new), encoding="utf-8")
    print(f"   + {path.name}: {label}")


HEX = "".join(f"{b:02x}" for b in CODE)

# ------------------------------------------------------------ 1 payloads dict
sub_once(BP, "PAYLOADS = {\n",
         "PAYLOADS = {\n"
         f"    'smoke': (\n        bytes.fromhex('{HEX}'),\n"
         f"        '{SRC_SHA}',  # smoke_agent ASM_SOURCE sha; see build_smoke\n    ),\n",
         "PAYLOADS['smoke']")

# -------------------------------------------------------- 2 buffer_script.py
sub_once(BS, 'INSTALL_RESIDENT = "install-resident"\n',
         'INSTALL_RESIDENT = "install-resident"\n'
         'SMOKE = "smoke"                      # scratchpad/smoke_agent.py: staged proxy probe\n',
         "SMOKE constant")

BUILD_SMOKE = '''
# poke-m1n1 stage runner: scratchpad/smoke_agent.py assembles deterministically into
# PAYLOADS['smoke']; params are data slots at a FIXED image offset (see register-smoke-script).
# Every scripted message runs the same image once (its step cursor rides client->param, epoch-
# keyed by nonce); each pass answers a constant 0x140-byte frame [0x40 header | window]. Stages
# ride --dump-blocks: 1 INIT probe, 2 +DUMP, 3 +POKE, 4 full verdict walk.
SMOKE_PARAM_OFFSET = %d
SMOKE_REPLY_SIZE = 0x140


def build_smoke(nonce=0x5CB00B1E, dump_src=0x08000000, dump_len=0x100,
                poke_addr=0, poke_val=0):
    """The smoke agent payload with its param block filled."""
    code = bytearray(payload(SMOKE))
    for offset, value in ((SMOKE_PARAM_OFFSET, nonce),
                          (SMOKE_PARAM_OFFSET + 0x04, dump_src),
                          (SMOKE_PARAM_OFFSET + 0x08, dump_len),
                          (SMOKE_PARAM_OFFSET + 0x0C, poke_addr),
                          (SMOKE_PARAM_OFFSET + 0x10, poke_val)):
        code[offset:offset + 4] = (int(value) & 0xFFFFFFFF).to_bytes(4, "little")
    assert int.from_bytes(bytes(code[SMOKE_PARAM_OFFSET + 0x14:])[:4], "little") == %d
    return bytes(code)


def parse_smoke_frame(frame):
    """-> dict view of one 0x140-byte pass reply [smoke_agent.py slab map]."""
    frame = bytes(frame)
    if len(frame) < SMOKE_REPLY_SIZE:
        raise ValueError(f"a smoke frame is {SMOKE_REPLY_SIZE} bytes, got {len(frame)}")
    w = lambda off: int.from_bytes(frame[off:off + 4], "little")
    n = w(0x1C)
    return {"magic_ok": w(0x00) == 0x314B4D53, "version": w(0x04), "nonce": w(0x08),
            "invocations": w(0x0C), "last_phase": w(0x10), "err": w(0x14),
            "dump_src": w(0x18), "dump_len": n, "poke_readback": w(0x20),
            "passes_done": w(0x24), "window": frame[0x40:0x40 + min(n, 0x100)]}


''' % (PARAM_OFF, 0xD0A6F00D)

anchor_bm = "def build_install_resident("
text = BS.read_text(encoding="utf-8")
if "def build_smoke(" not in text:
    i = text.index(anchor_bm)
    BS.write_text(text[:i] + BUILD_SMOKE.lstrip("\n") + text[i:], encoding="utf-8")
    print("   + buffer_script.py: build_smoke/parse_smoke_frame")
else:
    print("   = buffer_script.py: builders present")

sub_once(BS, """    INSTALL_RESIDENT: BufferScriptSpec(
        INSTALL_RESIDENT,
        "copy a resident hook into the top of EWRAM and install it in gIntrTable[4], where it runs "
        "every frame until a soft reset; answers with the V-blank handler it found "
        "(--resident turbo, --resident-param extra=N field=N battle=N hold=0x100 budget=228; needs --write-unsafe)",
        None),
}""",
"""    INSTALL_RESIDENT: BufferScriptSpec(
        INSTALL_RESIDENT,
        "copy a resident hook into the top of EWRAM and install it in gIntrTable[4], where it runs "
        "every frame until a soft reset; answers with the V-blank handler it found "
        "(--resident turbo, --resident-param extra=N field=N battle=N hold=0x100 budget=228; needs --write-unsafe)",
        None),
    SMOKE: BufferScriptSpec(
        SMOKE,
        "poke-m1n1 staged probe: ONE join walks INIT (stamp the EWRAM slab + count epochs), "
        "DUMP (range-checked copy into the reply), POKE (one word + read-back) and READ "
        "(verdict), each scripted message answering a 0x140-byte slab frame; --dump-blocks N "
        "picks how far the walk gets (--smoke-* parameterize it; persistence U1a/U2 verdicts "
        "ride the frames)",
        None),
}""", "SCRIPT_REGISTRY[SMOKE]")

sub_once(BS, "DUMP_SCRIPTS = frozenset({\n    MEMORY_DUMP, MEMORY_DUMP_MULTI, MEMORY_DUMP_SCATTER, SAVE_DUMP, ANCHORS, SAVE_WRITE,",
         "DUMP_SCRIPTS = frozenset({\n    MEMORY_DUMP, MEMORY_DUMP_MULTI, MEMORY_DUMP_SCATTER, SAVE_DUMP, ANCHORS, SAVE_WRITE, SMOKE,",
         "DUMP_SCRIPTS += SMOKE")

# ------------------------------------------------------------- 3 config.py
sub_once(CFG, "    resident_name: str | None = None\n",
         "    # smoke: the staged poke-m1n1 probe parameter block [scratchpad/smoke_agent.py].\n"
         "    smoke_nonce: int = 0x5CB00B1E\n"
         "    smoke_dump_src: int = 0x08000000\n"
         "    smoke_dump_len: int = 0x100\n"
         "    smoke_poke_addr: int = 0\n"
         "    smoke_poke_val: int = 0\n"
         "    resident_name: str | None = None\n",
         "smoke_* payload fields")

sub_once(CFG, """        if self.dump_blocks != 1 and self.script not in (buffer_script.MEMORY_DUMP_MULTI,
                                                         buffer_script.MEMORY_DUMP_SCATTER):
            raise ValueError(
                f"more than one block per session is only {buffer_script.MEMORY_DUMP_MULTI} and "
                f"{buffer_script.MEMORY_DUMP_SCATTER}; every other payload answers once")""",
         """        if self.script == buffer_script.SMOKE:
            object.__setattr__(self, "dump_size", buffer_script.SMOKE_REPLY_SIZE)
        if self.dump_blocks != 1 and self.script not in (buffer_script.MEMORY_DUMP_MULTI,
                                                         buffer_script.MEMORY_DUMP_SCATTER,
                                                         buffer_script.SMOKE):
            raise ValueError(
                f"more than one block per session is only {buffer_script.MEMORY_DUMP_MULTI}, "
                f"{buffer_script.MEMORY_DUMP_SCATTER} and {buffer_script.SMOKE}; every other "
                "payload answers once")""",
         "multi-block allowance + forced reply size")

sub_once(CFG, """        if self.script == buffer_script.INSTALL_RESIDENT:
            return buffer_script.build_install_resident(
                self.resident_name, build=build, **dict(self.resident_params))""",
         """        if self.script == buffer_script.SMOKE:
            return buffer_script.build_smoke(
                self.smoke_nonce, self.smoke_dump_src, self.smoke_dump_len,
                self.smoke_poke_addr, self.smoke_poke_val)
        if self.script == buffer_script.INSTALL_RESIDENT:
            return buffer_script.build_install_resident(
                self.resident_name, build=build, **dict(self.resident_params))""",
         "build_code branch")

# ----------------------------------------------------------- 4 host CLI
FLAG_BLOCK = '''    parser.add_argument(
        "--smoke-nonce", type=lambda v: int(v, 0), default=0x5CB00B1E, metavar="VALUE",
        help=("with --buffer-script smoke: the per-run epoch stamp compared against the EWRAM "
              "slab so a stale cursor restarts the walk (accepts 0x hex)"))
    parser.add_argument(
        "--smoke-dump-src", type=lambda v: int(v, 0), default=0x08000000, metavar="ADDR",
        help=("with --buffer-script smoke: the DUMP step's source (RAM/ROM only; the payload "
              "refuses IO ranges)"))
    parser.add_argument(
        "--smoke-dump-len", type=lambda v: int(v, 0), default=0x100, metavar="N",
        help="with --buffer-script smoke: the DUMP step's length, <=0x3C0, multiple of 4")
    parser.add_argument(
        "--smoke-poke-addr", type=lambda v: int(v, 0), default=0, metavar="ADDR",
        help=("with --buffer-script smoke: the POKE step's aligned RAM address (0 skips the "
              "store and still reports)"))
    parser.add_argument(
        "--smoke-poke-val", type=lambda v: int(v, 0), default=0, metavar="VALUE",
        help="with --buffer-script smoke: the POKE step's word")
'''
sub_once(HOST, "    parser.add_argument(\n        \"--resident\", default=None,",
         FLAG_BLOCK + "    parser.add_argument(\n        \"--resident\", default=None,",
         "--smoke-* flags")

sub_once(HOST, "                resident_name=args.resident, resident_params=tuple(resident_params),",
         "                smoke_nonce=args.smoke_nonce, smoke_dump_src=args.smoke_dump_src,\n"
         "                smoke_dump_len=args.smoke_dump_len, smoke_poke_addr=args.smoke_poke_addr,\n"
         "                smoke_poke_val=args.smoke_poke_val,\n"
         "                resident_name=args.resident, resident_params=tuple(resident_params),",
         "payload kwargs")

print("(host flag insertion checks ordering below)")
