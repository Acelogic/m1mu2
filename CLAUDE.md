# Prompt for Claude — implement m1mu² (bench orchestrator for FRLG memory-read probes)

You are implementing **m1mu²**, a benign developer-diagnostic tool for our licensed retail copy of
Pokémon FireRed running inside the Game Boy Advance compatibility runtime. It lets us READ
game memory over our bench-owned radio test-rig whenever the game sits on its Mystery Gift screen.
Think serial-console convenience, not novelty: Python on the bench ⇄ tiny THUMB measurement scripts
injected through the existing Mystery-Gift host ⇒ structured results back out. Nothing we do writes
game flash by default or leaves anything behind when the console powers off normally.

## Repo & ground truth
- You own this clean-room workspace at `/Users/mcruz/Developer/pokebench` — nothing above it exists for you. Bench toolchain venv: `.venv/bin/python` (uv-managed py3.13).
- The battle-tested host stack lives at
  `pocs/FireRedPoC/local-data/pokeldn-lab/pokeldn-src/` — study `bin/frlg_mg_host.py --help` and
  `pokeldn/frlg/rom/buffer_script.py` BEFORE writing any code; embed Unicorn self-tests there document
  verified behavior. Never re-implement parsing: import their `parse_sloop_svc`, `read_call_chain`,
  `describe_table_scan`, etc.
- ESP radio identity: only the MAC from `esptool --port <P> read_mac` counts (current spare board
  20:50:0d:d1:15:20 on `/dev/cu.usbserial-0001`). Verify-before-trust ladder documented in the
  `pokeldn-esp32-rig` skill; always finish esptool with `--after hard-reset`.
- Live hosting needs root while preserving env: `sudo -nE .venv/bin/python ... POKELDN_RADIO=esp32:$PORT`
  (export first!). A conda crash-report spam on stderr after failures is known noise; judge runs ONLY
  by the tee'd log files under `captures/`.

## Hardware semantics that shape the design (non-negotiable)
1. One "join" = one session carrying ONE compiled THUMB trap program of up to **8 steps**; steps run
   in order; call-chain steps may pipe `[prev]` pointer returns into later reads/writes. swi and bkpt
   modes cannot mix within one join.
2. Console precondition: the game must sit on Mystery Gift → friends search/waiting screen (human sets
   this up; CLI must PAUSE and confirm before each live join, never silently fire radio).
3. Read-only by default: refuse anything but the documented safe syscall set unless operator passes
   explicit `--allow-unsafe`; NEVER pass flash-writing flags implicitly. Reads outside mapped guest
   ranges fault the core — keep a denylist module mirroring host-side guard windows.
4. Crash signature mid-join = delivered blocks stop, idle-frame counter balloons, RFU disconnect
   arrives. Treat as telemetry: classify last successfully-echoed step (records echo their THUMB
   call-site word, e.g. 0xDFnn) so batches bisect automatically.
5. Join economy discipline: default budget 2 joins per invocation, verify-after-risk rule: any risky
   batch must be followed by a configured health-check reader pair (park-check + error-flag SVC numbers
   already used across the repo scripts).

## Deliverables (this milestone)
1. Package `m1mu2/` (dir exists: framing self-tested): modules
   - `pack.py`: Python mini-language → join programs. e.g. `probe.call("Random"), probe.read32(prev+0x10)`
     compiled to ≤8-step sloop-svc / call-chain invocations using builder functions from buffer_script.
   - `session.py`: subprocess-wraps frlg_mg_host.py (exact flag vocabulary mined above); pause-confirm
     human gate; tee capture to `captures/m1mu2/<utcstamp>-<name>.log(+.bin)`; exit-status never trusted alone.
   - `result.py`: uses upstream `read_*`/`describe_*` helpers; typed Result objects w/ provenance links
     (log path, seq, echoed call-site words).
   - `journal.py`: append-only JSONL beside captures replayable offline (`python -m m1mu2.replay`).
   - `cli.py`: `m1mu2 repl` exposing terse expressions: `.call NAME args`, `.peek ADDR[ len]`, `.steps [...]`,
     `.budget N`, `.go [label]`. Plus non-interactive `m1mu2 run script.muprog`.
2. Loopback unit tests (pytest, no hardware): compile→decompile golden programs vs expected argv lists;
   feed captured real logs/fixtures through result parsers; crash-injection fixture asserts correct
   bisection point. All green before any radio is touched.
3. README.md documenting safety posture (reads only, RAM-resident artifacts vanish with normal power-off,
   zero modifications to shipped game data) and the two-command quickstart once hardware is present.

## Style & rules
- Match existing repo conventions (look around pokeldn-src for naming/log idioms). Small PR-sized commits
  with imperative messages; keep `git status` clean; never commit `captures/` binaries beyond small fixtures.
- If you find behavior contradicting the semantics list above, trust observation, then REPORT it explicitly
  rather than quietly papering over it.
- Definition of done for this milestone: pytest green; CLI opens; composing a 3-step read program produces
  exact intended frlg_mg_host.py command line visible via `--dry-run` (implement --dry-run rendering too).

## Appendix: ESP32 radio-rig operations cheat-sheet (verified procedures)

The rig is an ESP32-D0WD-V3 board behind CP2102 serial (`/dev/cu.usbserial-*`) speaking our framing to
the bench Python; it hosts/joins the game's ad-hoc network via raw frame injection. Procedures below are
already proven — follow them exactly; each exists because something once went subtly wrong otherwise.

### Identity & health check (run before ANY live join; cache results per session)
1. Ports: `ls /dev/cu.usbserial-*` (never assume names across machines; fresh plug-in = newest entry).
2. Board identity: `.venv/bin/python -m esptool --port $P --after hard-reset read_mac`
   — known-good MACs: `20:50:0d:d1:15:20` spare (certified), production unit ends `ce:78:1c`. Boards are
   interchangeable and USB strings identical ⇒ ONLY the MAC identifies a board; tag all data with it.
   ALWAYS keep `--after hard-reset`: otherwise chip parks in ROM bootloader and every later handshake
   mimics an unflashed board.
3. App-level heartbeat (decisive):
   `POKELDN_RADIO=esp32:$P .venv/bin/python pocs/FireRedPoC/local-data/pokeldn-lab/pokeldn-src/tools/ldn/ldn_scan.py \
    --keys keys/prod.keys \
    --channels 1 --dwell 1`
   Clean exit + `found 0 network(s)` == HEALTHY while console idles (zero nets is expected, not failure).
   `RadioError: no reply 0x81 to command 0x01` ⇒ firmware missing/foreign. Scanner accepts only {1,6,11,36,40,44,48}.
4. RX-quality spot-check when receiver suspected: drive driver class directly (sniff ch6 ~5 s, expect
   ≳1000 records on busy channel); do NOT debug-monitor via raw pyserial (boot ROM @115200 vs app logs
   @921600 makes single-baud captures look like garbage).

### Running experiment joins (what m1mu² wraps)
From repo root, note ordering matters (env must survive sudo):
```
export POKELDN_RADIO=esp32:/dev/cu.usbserial-0001
sudo -nE .venv/bin/python pocs/FireRedPoC/local-data/pokeldn-lab/pokeldn-src/bin/frlg_mg_host.py \
  --keys <absolute prod.keys path> --buffer-script sloop-svc --svc-number 0x53 --svc-number 0x4A \
  [--dump-file captures/NAME.bin] | tee captures/NAME.log
```
- Root mandatory for injection (`error: live LDN hosting requires root`); `-E` preserves POKELDN_RADIO —
  without it you get misleading "`visible PHYs: none`" that means env got reset, NOT broken hardware.
- Game MUST sit on Mystery Gift → friends search/waiting screen first (human step; confirm visually).
  Launching with game elsewhere = ghost run: SSID broadcast, exit 0, near-empty log, zero gift traffic.
- ≤8 `--svc-number` per invocation execute as ONE program; swi-vs-bkpt modes never mix per join;
  non-read-only numbers need explicit `--write-unsafe`; flash verbs demand their own consent flags.
- Judge ONLY tee'd logs (miniforge crash-report noise pollutes stderr post-failure; ghosts exit 0).
- Two joins max per working session, risky batches bookended by verification readers (0x53/0x4A pair);
  any fault => halt sequence, let console save+close normally, record scoreboard line.

### Recovery/reflash (only if heartbeat fails AND forensics says foreign/blank image)
Read-back probe: `esptool … read_flash 0x1000 0x100 fw_head.bin`, hexdump: 0xFF everywhere=blank;
first byte 0xE9 with headers unlike `pocs/.../firmware/esp32/build/*.bin` (ours carries `esp_ldn_radio`
magic ~offset 0x2C) = foreign-but-flashable. Rebuild: source `~/esp/esp-idf` export.sh, cd
`.../pokeldn-src/firmware/esp32 && idf.py set-target esp32 && idf.py build && idf.py -p $P flash`
(success marker literally `Hash of data verified.`), or faster with existing artifacts per
`build/flash_args` offsets (0x1000 bootloader, 0x8000 partition-table, 0x10000 pokeldn_radio.bin).
Board-specific CONFIG target mismatch (C/S-series vs classic) bricks-blind — read silkscreen/chip info first.

