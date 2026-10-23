# m1mu²

<p align="center">
  <img src="assets/m1mu2-banner.png" alt="M1μ² — memory probing workbench" width="100%">
</p>

**Memory probing for Switch 2 through ns2jb, with a separate FireRed/GBA backend.**

m1mu² provides a command-line workbench, interactive REPL, and local capture viewer for
inspecting memory and keeping reproducible results. Switch 2 support integrates with an existing
[ns2jb](https://gitlab.com/pepsipu/ns2jb) session: inspect saved captures, probe the application's
native RPC, and perform bounded reads through a qualified retained filesystem-service endpoint.
See [pepsipu's Switch 2 jailbreak write-up](https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb/)
for the underlying jailbreak and its broader capabilities.

The FireRed backend probes the game's GBA runtime through the vendored Mystery Gift host.
The two backends use separate transports and address spaces.

## Current support

| Capability | Status |
|---|---|
| Switch 2 application RPC probing | **Live read recorded on October 22, 2026:** 32 SDK instruction bytes matched the saved signature; offline replay passed. |
| Switch 2 capture inspection, REPL, and browser viewer | Available; saved captures can be inspected without contacting the console. |
| Switch 2 retained FS/sysmodule memory reads | Adapter implemented and verified against local protocol fixtures. **Live FS acquisition remains unqualified** in the recorded session. |
| FireRed/GBA probing | Existing Mystery Gift workflow, including a saved hardware health-probe capture and offline replay. |

The application probe establishes a narrow readback result. USER/SYSTEM mounts, Mario Kart World
files/assets, and live FS sysmodule reads have not been demonstrated by m1mu². The workbench
uses existing sessions; it does not run the jailbreak or install a native payload.

## Setup

Use **Python 3.13 or newer**. The Switch backend uses the Python standard library and requires
a POSIX host such as macOS or Linux for file locking and UNIX sockets.

```bash
git clone https://github.com/Acelogic/m1mu2.git
cd m1mu2
python3.13 -m venv .venv
.venv/bin/python -m m1mu2 --help
```

Run the examples from the repository root. `ns2` (alias `switch2`) selects Switch 2;
`frlg` selects FireRed. Existing `repl` and `run` commands retain their FireRed behavior.
For FireRed and its regression suite, also install the host dependencies:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

## Switch 2 / ns2jb

The adapter expects the session files, qualification reports, and bridge endpoints from the
existing ns2jb/Explorer bench setup. These are external prerequisites, not created by m1mu².
Application probing uses the local HTTP RPC bridge; retained FS reads additionally use its
memory-reader UNIX socket. Importing this backend does not load the FireRed host or its radio.

### Inspect an existing session

Select your own session directory. These commands inspect local evidence without contacting
the console:

```bash
export M1MU2_SESSION="/absolute/path/to/ns2-explorer/.state/session-YOUR-ID"

.venv/bin/python -m m1mu2 ns2 status --session-dir "$M1MU2_SESSION"
.venv/bin/python -m m1mu2 ns2 captures --session-dir "$M1MU2_SESSION"
.venv/bin/python -m m1mu2 ns2 repl --session-dir "$M1MU2_SESSION"
.venv/bin/python -m m1mu2 ns2 view --session-dir "$M1MU2_SESSION" --port 8788
```

Open <http://127.0.0.1:8788/> for the passive viewer. It shows acquisition stages, hex previews,
and downloads of complete, hash-verified captures. Refresh reads local files only. Control files
whose addresses are unknown remain labeled as evidence rather than mapped sysmodule memory.

The REPL supports `status`, `captures`, `rpc-probe`, `read ADDRESS LENGTH` (alias `peek`),
`replay RECEIPT`, `help`, and `quit`. Session/report selection and live mode are fixed at startup.
It does not evaluate Python or shell commands. A failed command halts the session without
retrying a read.

### Probe the application RPC

`rpc-probe` reads exactly 32 bytes at the selected session's SDK + `0x4CC0` and compares them
with its saved instruction signature. It requires completed application qualification and
confirmed acquisition cleanup, and verifies the RX mapping before and after the read.
An idle, qualified application's RPC can be probed even when FS acquisition did not succeed.

```bash
# Inspect the plan without contacting the console:
.venv/bin/python -m m1mu2 ns2 rpc-probe --session-dir "$M1MU2_SESSION"

# Perform the fixed probe on the qualified, idle session:
.venv/bin/python -m m1mu2 ns2 rpc-probe --session-dir "$M1MU2_SESSION" --live
```

For interactive probing, start `ns2 repl --session-dir "$M1MU2_SESSION" --live`, then enter
`rpc-probe` and `quit`. The native RPC updates its own scratch output; it does not write the
probed code. This command does not expose arbitrary reads or qualify FS sysmodule access.

### Bounded FS reads and replay

`ns2 read` requires `--session-dir`, `--report`, `--address`, and `--length`. The address range
must lie wholly inside a prior complete, verified capture from the selected acquisition report.
Use `ns2 read --help` for the CLI options, or start the REPL with `--report PATH` and enter `help`.

Reads default to dry-run. `--live` enables the existing retained reader, with a maximum of
6 MiB per request. Session, report, boot identity, endpoint ownership, readiness, pending
operations, capture hashes, and response lengths are checked before accepting bytes. Active
Explorer acquisitions are refused. An upstream retained read can change its internal pointer
state; the requested target bytes are not written.

Each successful live read or application probe saves a new read-only `.bin`, a JSON receipt,
and a journal entry under `captures/ns2/` (or `--captures`). Receipts record session identity,
source, address, length, and SHA-256 without credentials. Replay verifies the saved bytes offline:

```bash
.venv/bin/python -m m1mu2 ns2 replay --capture /absolute/path/to/capture-receipt.json
```

Never reuse a session directory after restarting or reconnecting the Switch. The per-session
lock coordinates m1mu² readers only; keep other clients off the same endpoint during a read.
Ambiguous hardware requests are never retried automatically. A bridge `status` response reports
local readiness; matching readback bytes provide the application-probe evidence.

### Recorded hardware result

On **October 22, 2026 at 19:20 UTC**, `rpc-probe` passed through the m1mu² REPL: 32 bytes at
SDK + `0x4CC0` matched the saved instruction signature, with matching RX maps before and after.
Offline replay also passed. The [published readback summary](verification/recorded/ns2-rpc-20261022.json)
preserves the result, source hashes, and SHA-256 of the [32 captured bytes](verification/recorded/ns2-rpc-20261022.bin).
It is a sanitized derivative of the local run receipt, with session identifiers and host paths
omitted, rather than a receipt accepted by `ns2 replay`. Its scope is `application-sdk`;
it does not independently attest the hardware identity. Verify the published bytes with:

```bash
shasum -a 256 verification/recorded/ns2-rpc-20261022.bin
```

FS acquisition in that session had stopped at
`Field copy did not qualify within its attempt limit: combined-leak-0-1`, with cleanup acknowledged.
The successful application probe does not change that FS result. No game patches were applied.

## FireRed / GBA backend

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

### FireRed safety posture

- **Dry-run is the default.** Nothing reaches the radio unless you pass `--live`, and even then
  every join stops at a confirmation prompt that restates the console precondition (Mystery Gift →
  friends search/waiting screen, set up by hand). Every command line — dry or live — is first run
  through the host's own option parser, run config and payload build in-process
  (`m1mu2.upstream.check_host_argv`), so anything the host would refuse is refused before the host
  starts.
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
  writes the console's memory, its save, or flash; the cartridge ROM is never written.
- **The game saves at the end of every join.** The host logs of the first live joins (2026-10-15)
  show the game doing its own normal save as each buffer-script session closes: "Console finished
  the gift and asked to close the link; holding the network open while it saves.", then "The
  console printed our message and saved." That is the game's own end-of-Mystery-Gift save of
  whatever state it is in, not a write by the payload or by m1mu², and m1mu² can neither skip nor
  change it. The host's buffer-script path sends no Wonder Card and replaces none.
- **Join economy.** Two live joins per invocation by default (`--budget N`). A *risky* join —
  anything that needed the override, or a read through a pointer the console fetched from memory —
  is always followed by the health pair (`swi 0x53, 0x4A`), and the schedule is refused up front if
  the budget cannot cover both. Any crash, ghost or missing answer halts the sequence: let the
  console save and close normally.
- **Logs decide, exit codes do not.** Each live join tees the host's stdout to
  `captures/m1mu2/<utcstamp>-<label>.log`, the answer block to `.bin`, stderr (known miniforge
  crash-report noise) to `.stderr.log`, and journals everything to `captures/m1mu2/journal.jsonl`
  (append-only, replayable offline with `python -m m1mu2.replay`).

### FireRed quickstart (once hardware is present)

The venv needs everything in `requirements.txt` (`pytest` fails if the live path's imports do not
resolve). Run the rig's identity and heartbeat checks from CLAUDE.md's appendix first (esptool
`read_mac` with `--after hard-reset`, then `ldn_scan.py`), put the console on Mystery Gift →
friends search, then:

```bash
.venv/bin/python -m m1mu2.cli run probes/health.muprog
```

```bash
.venv/bin/python -m m1mu2.cli run probes/health.muprog --live --no-sudo --mac YOUR_CONSOLE_MAC
```

The first prints the exact command and the host's verdict on it; the second fires it after your
confirmation. `--no-sudo` runs the host as you instead of under `sudo -nE`: the ESP32 path does
not need root (item 8 below), and your captures stay owned by you. Without it, `sudo -nE` needs
cached credentials, and macOS caches them per terminal: a `sudo -v` only counts in the terminal
that then runs m1mu², and a shell with no terminal (an agent's) never has any, so the join comes
back `not-started`.

### What a FireRed join is

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
| `m1mu2/entry.py` | selects Switch 2 or FireRed; preserves the existing `repl` and `run` commands |
| `m1mu2/ns2.py` | Switch session checks, capture inspection, bounded retained reads, replay, and REPL |
| `m1mu2/ns2_rpc.py` | fixed application SDK probe through an existing qualified RPC bridge |
| `m1mu2/ns2_view.py`, `m1mu2/ns2_view.html` | passive local Switch capture viewer |
| `m1mu2/upstream.py` | imports `pokeldn-src` in place; `check_host_argv` = the host's own validation, offline |
| `m1mu2/policy.py` | what goes without `--allow-unsafe`, and what never goes |
| `m1mu2/pack.py` | steps → joins → buffer-script argv, and back (`join_from_host_args`) |
| `m1mu2/session.py` | budget, verify-after-risk scheduling, confirm gate, host invocation (`sudo -nE` or `--no-sudo`), tee |
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
   → 1, Ctrl-C → 130, `--idle-timeout` → 124. CLAUDE.md says ghost runs exit 0. Live, both
   answered joins of 2026-10-15 exited 0.
8. Root is not needed on the ESP32 path. `pokeldn.host_support.needs_root()` is False whenever
   `POKELDN_RADIO=esp32:…` is set, so the host's own "requires root" error appears only when that
   variable was lost (e.g. `sudo` without `-E`). Verified live on 2026-10-15: the same health join
   answered identically under `sudo -nE` and with `--no-sudo` (same registers, byte-identical
   `.bin`). m1mu² keeps `sudo -nE` as the default because the brief asks for it; `--no-sudo` drops
   it and is what the quickstart uses. Under `sudo` the host writes a root-owned `.bin`.
9. Paths and environment: the stack lives at `pokeldn-src/`, not `pocs/FireRedPoC/…`; there is no
   `pokeldn-esp32-rig` skill here; `unicorn` is absent from the venv. The venv also could not run
   the live path at all: `python-netlink==0.0.15` (pinned by `pokeldn-src/vendor/LDN/setup.py`,
   imported by `ldn.wlan`) and `zstandard==0.25.0` (`pokeldn-src/requirements.txt`) were missing,
   so `ldn_scan.py` died on `import netlink` and the host would have too, after `go`. Every offline
   test stops before the transport, so nothing caught it. Both are now in `requirements.txt`, and
   `tests/test_env.py` imports the live path's modules so a venv without them fails `pytest`.

## Verification

Switch E2E checks run the actual CLI, REPL, and viewer against deterministic local fixtures:

```bash
.venv/bin/python verification/ns2_e2e.py
.venv/bin/python verification/ns2_view_e2e.py
.venv/bin/python verification/ns2_rpc_e2e.py
```

| Harness | Coverage | Repeatable artifact |
|---|---|---|
| `ns2_e2e.py` | CLI/REPL, HTTP/UNIX reader protocol, capture integrity, refusals, and replay | `verification/artifacts/ns2-*/receipt.json`, transcripts, and captures |
| `ns2_view_e2e.py` | Viewer HTTP interface, byte-identical downloads, tamper rejection, foreign Host rejection, and refusal of device operations | `verification/ns2_view_receipt.json` |
| `ns2_rpc_e2e.py` | Application probe through CLI/REPL, qualification checks, failures, and replay | `verification/artifacts/ns2-rpc-*/receipt.json` |

These are software/protocol checks. Each harness prints its receipt location; generated run
artifacts stay local. The separate dated readback summary above documents the recorded live
application read and its limits.

Run the existing FireRed regression suite after installing `requirements.txt`:

```bash
.venv/bin/python -m pytest
```

The FireRed suite uses no hardware, host subprocess, or `sudo`. Most result-parser fixtures are **synthetic**
(answer blocks and logs built to the documented formats), so they can cover crashes, ghosts and
stops. `tests/fixtures/real/` holds the first hardware capture, the answered health join of
2026-10-15, which `tests/test_real_capture.py` classifies. Upstream's Unicorn self-tests do not run
here (`unicorn` is not in the venv).
