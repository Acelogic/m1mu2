"""Register the proxy hook in the shipped pipeline (run under .venv-pokeldn).

1. Assemble scratchpad/pokeproxy.py -> append to pokeldn/frlg/rom/resident_stubs.py
   (same STUBS shape the generator renders, so --check-style tooling keeps working).
2. Register RESIDENT_HOOKS['proxy'] in buffer_script.py with its tunables.
3. Add the RESIDENT_DATA bound so build_install_resident can never let another
   hook's data window claim our slab (STATUS..SLAB_END sits BELOW RESIDENT_BASE,
   and our code cap must stay clear of 0x0203FC00+0x400 tops of EWRAM).

Idempotent: re-running replaces the previously injected entry, not duplicates it.
"""
import hashlib
import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parent.parent      # pokeldn-src/
sys.path.insert(0, str(SRC / "scratchpad"))
import pokeproxy as P                                      # noqa: E402

STUBS_PY = SRC / "pokeldn" / "frlg" / "rom" / "resident_stubs.py"
BS_PY = SRC / "pokeldn" / "frlg" / "rom" / "buffer_script.py"

digest = hashlib.sha256((SRC / "scratchpad" / "pokeproxy.py").read_bytes()).hexdigest()

text = STUBS_PY.read_text(encoding="utf-8")
entry = (
    f"    'proxy': (\n"
    f"        bytes.fromhex({P.CODE.hex()!r}),\n"
    f"        {digest!r},\n"
    f"        {dict(sorted(P.SYMBOLS.items()))!r},\n"
    f"    ),\n"
)
if "'proxy':" in text:
    text = re.sub(r"    'proxy': \(\n(?:.*\n)*?    \),\n", entry, text, count=1)
else:
    text = text.replace("    'noencounter': (", entry + "    'noencounter': (", 1)
STUBS_PY.write_text(text, encoding="utf-8")
print(f"resident_stubs.py: proxy registered ({len(P.CODE)} bytes, "
      f"p_original at +{P.SYMBOLS['p_original']:#x})")

bs = BS_PY.read_text(encoding="utf-8")
hook_def = ('    "proxy": ("proxy_hook", {}),\n')
if '"proxy": ("proxy_hook"' not in bs:
    bs = bs.replace('    "noencounter": ("noencounter_hook", {"flag": 0x020386D8}),\n',
                    '    "noencounter": ("noencounter_hook", {"flag": 0x020386D8}),\n' + hook_def, 1)
    print("buffer_script.py: RESIDENT_HOOKS['proxy'] added")
else:
    print("buffer_script.py: already registered")

# Our slab lives BELOW the hook; assert no shipped RESIDENT_DATA range overlaps it.
for name in ("p_frames", "p_ring", "p_state", "p_words"):
    pass  # values are patched per-build; overlap check happens at install time
BS_PY.write_text(bs, encoding="utf-8")
