# m1mu²

Bench orchestrator for read-only memory probes on our licensed FireRed cartridge, running in the
Switch's GBA runtime, through the vendored Mystery Gift host (`pokeldn-src/bin/frlg_mg_host.py`).
You write a few steps, m1mu² compiles them into the one buffer-script program a join carries,
shows you the exact host command line, checks it against the host's own parser and builders
offline, and (only with `--live`, only after you confirm the console is on the right screen)
runs it and turns the tee'd log and answer block into typed results.

```
.venv/bin/python -m m1mu2.cli repl                 # dry-run by default
m1mu2> .call GetVarPointer 0x4024
m1mu2> .peek prev 2
m1mu2> .peek 0x030042D0
m1mu2> .go var4024
```

## Safety posture

- **Dry-run is the default.** Nothing reaches the radio unless you pass `--live`, and even then
  every join stops at a confirmation prompt that restates the console precondition (Mystery Gift →
  friends search/waiting screen, set up by hand). Every command line — dry or live — is first run
  through the host's own option parser, run config and payload build in-process
  (`m1mu2.upstream.check_host_argv`), so anything the host would refuse is refused before `sudo`.
- **Reads only by default.** `m1mu2/policy.py` is narrower than the host's guards and runs on top
  of them, never instead of them:
  - syscalls: only those seen answering without side effects on hardware — `0x49 0x4A 0x4B 0x50
    0x52 0x53 0x54`, plus the bad-word check `0x4D` on the payload's own copy of the data;
  - chain calls: only getters (`FlagGet VarGet GetVarPointer GetMoney CheckBagHasItem
    CheckBagHasSpace IsEnoughMoney ItemIsMail SpeciesToNationalPokedexNum CalcCRC16
    StringCompare`); `Random`/`SeedRng` advance the RNG and need the override;
  - reads: literal targets in EWRAM, IWRAM or the 16 MB cartridge; I/O, palette, VRAM, OAM and the
    cartridge window past 16 MB need the override; unmapped addresses never go.
  Anything else needs an explicit `--allow-unsafe`, and m1mu² passes the host's `--write-unsafe`
  only when that override was given *and* the host requires it. Never, override or not:
  `swi 0x48 0x4C 0x55 0x56` (flash sector write, finished save, SaveBlock2 hand-over,
  ReplaceSector) and `bkpt #0x52`.
- **Nothing is left behind by default.** The payloads and their result blocks live in EWRAM
  (`gDecompressionBuffer` and the scratch above it) and are gone at power-off. No default program
  writes the console's memory, its save, or flash; the cartridge ROM is never written. *Not
  verified here:* whether the game itself commits its normal save at the end of a buffer-script
  Mystery Gift session — m1mu² does not change that behaviour either way.
- **Join economy.** Two live joins per invocation by default (`--budget N`). A *risky* join —
  anything that needed the override, or a read through a pointer the console fetched from memory —
  is always followed by the health pair (`swi 0x53, 0x4A`), and the schedule is refused up front if
  the budget cannot cover both. Any crash, ghost or missing answer halts the sequence: let the
  console save and close normally.
- **Logs decide, exit codes do not.** Each live join tees the host's stdout to
  `captures/m1mu2/<utcstamp>-<label>.log`, the answer block to `.bin`, stderr (known miniforge
  crash-report noise) to `.stderr.log`, and journals everything to `captures/m1mu2/journal.jsonl`
  (append-only, replayable offline with `python -m m1mu2.replay`).

## Quickstart (once hardware is present)

Run the rig's identity and heartbeat checks from CLAUDE.md's appendix first (esptool `read_mac`
with `--after hard-reset`, then `ldn_scan.py`), put the console on Mystery Gift → friends search,
then:

```bash
.venv/bin/python -m m1mu2.cli run probes/health.muprog
```

```bash
.venv/bin/python -m m1mu2.cli run probes/health.muprog --live --mac 20:50:0d:d1:15:20
```

The first prints the exact command and the host's verdict on it; the second fires it after your
confirmation (`sudo -nE` needs cached credentials: run `sudo -v` yourself beforehand).

## What a join is

One join runs one `--buffer-script`. Only two take steps, and they are different payloads
(`pokeldn-src/asm/sloop-svc.s`, `asm/call-chain.s`):

| | `sloop-svc` | `call-chain` |
|---|---|---|
| steps | ≤ 8 `--svc-number` (0x40..0x62) | ≤ 16 `--chain-step OP[+keep]:TARGET[,ARG…]` |
| operands | ONE r0..r3 and ONE ≤256-byte buffer shared by every call | per step; `prev`/`prev+N` as target or first arg |
| swi / bkpt | `--svc-bkpt` flips the whole program | no syscalls |
| answer | per call: echoed thunk word (`0x4770DFnn`) + r0..r3, then the data | executed/refused counts + one word per step |

`m1mu2.pack.compile_program` splits a mixed program into joins at every payload change, operand
change or size limit, and refuses a split that would need `prev` across the boundary.

**A crash mid-join returns nothing.** Both payloads point the console's outgoing message at their
result block only after every step has returned, so there is no "last echoed step" to read when
the core faults. m1mu² records the fault window (all N steps) and writes a bisection plan instead:
re-run prefixes (which keep every `prev` dependency intact), one prefix + health pair per default
budget, ⌈log₂ N⌉ probes worst case. It never spends joins on bisection by itself.

## Layout

| module | role |
|---|---|
| `m1mu2/upstream.py` | imports `pokeldn-src` in place; `check_host_argv` = the host's own validation, offline |
| `m1mu2/policy.py` | what goes without `--allow-unsafe`, and what never goes |
| `m1mu2/pack.py` | steps → joins → buffer-script argv, and back (`join_from_host_args`) |
| `m1mu2/session.py` | budget, verify-after-risk scheduling, confirm gate, `sudo -nE` invocation, tee |
| `m1mu2/result.py` | answer blocks via upstream parsers, log classification, bisection |
| `m1mu2/journal.py`, `m1mu2/replay.py` | append-only JSONL journal and offline replay |
| `m1mu2/cli.py` | `repl` and `run FILE.muprog` |

`pokeldn-src/` is vendored, read-only reference. m1mu² imports its builders and parsers and never
re-implements them. `m1mu2/frame.py`/`link.py` (COBS RPC framing) predate this milestone and are
not on the host path.

## Where the code disagrees with CLAUDE.md

Observed in `pokeldn-src/` while building this milestone; m1mu² follows the code.

1. "≤ 8 steps with `[prev]` piping, swi/bkpt never mixed" describes no single payload: sloop-svc is
   8 calls without `prev`; call-chain is 16 steps with `prev` and no syscalls.
2. Crash bisection by "last echoed step" is impossible inside a join (see above).
3. Upstream comments say `swi 0x55` must never go, but `SLOOP_REFUSED_NUMBERS` omits it
   (`0x56` is listed twice). m1mu² refuses it itself; `tests/test_policy.py` flags it if upstream
   is fixed.
4. Upstream's "read-only" syscall set is static analysis: 0x46, 0x4E, 0x58..0x60 were never issued
   from the Mystery Gift client, and 0x51 reads *and clears* the close-link flag.
5. Upstream lets every named chain call out without `--write-unsafe` (`FlagSet`, `VarSet`,
   `AddMoney`…).
6. The health pair's docs: 0x53 = status-screen exit flag, 0x4A = connect-period hold during
   SEARCH_PARENT. Both answer-only, but neither is documented as "park-check / error-flag".
7. Exit status: the host returns 0 only when a console joined and the engine succeeded; no console
   → 1, Ctrl-C → 130, `--idle-timeout` → 124. CLAUDE.md says ghost runs exit 0.
8. Root: `pokeldn.host_support.needs_root()` is False whenever `POKELDN_RADIO=esp32:…` is set, so
   the host's own "requires root" error appears only when that variable was lost (e.g. `sudo`
   without `-E`). m1mu² keeps `sudo -nE` as specified; whether the ESP32 path needs root at all is
   untested.
9. Paths: the stack lives at `pokeldn-src/`, not `pocs/FireRedPoC/…`; there is no
   `pokeldn-esp32-rig` skill here; `unicorn` is absent from the venv; no real captures exist.

## Tests

```bash
.venv/bin/python -m pytest
```

No hardware, no subprocess of the host, no `sudo`. Result-parser fixtures are **synthetic** —
answer blocks and logs built to the documented formats, since no real captures exist yet — and
upstream's Unicorn self-tests do not run here (`unicorn` is not in the venv).
