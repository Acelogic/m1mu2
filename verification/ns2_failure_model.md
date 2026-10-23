# Read-only Switch 2 backend failure model

Written before the backend and its subprocess verification harness.

The backend consumes an existing ns2jb retained endpoint. It never bootstraps,
installs, acquires, executes target code, selects a target explicitly, or writes
target bytes. Upstream retained reads can change their internal pointer state;
this is not a claim that the target performs no internal writes.

Failure cases and required behavior:

- Missing, malformed, oversized, or mismatched session/report/connection files:
  fail closed; do not infer a different session or endpoint.
- Explorer system-access has a running stage, or stages without a finished
  marker; retained or memory control has a pending/inflight operation: refuse
  before any transport. Offline status reports saved state only.
- Boot identity is stale, platform is not Switch 2, or boot is not ready:
  status RPC only, then stop. Never reuse an old ready flag.
- Retained endpoint does not confirm ready, reliable, noncorrupting operation,
  session, report, and corruption count: stop before reading.
- Noncanonical, empty, oversized (>6 MiB), or not previously fully captured
  memory: refuse before transport. Prior captures must have exact verified
  bytes, a matching SHA-256, an explicit address/length, and no partial/error
  marker. A reported file alone does not prove the requested range was captured.
- Output paths escape the supplied session directory, capture bytes are short,
  hashes differ, or response address/length/corruption count differ: reject the
  response. Preserve failure evidence without accepting a new capture.
- Session, connection, endpoint identity, or acquisition state changes during
  the operation: reject the result. The protocol has no shared exclusive lock,
  so snapshot checks reduce but cannot eliminate races with external clients.
- Timeout, connection close, malformed response, or ambiguous error: one attempt
  only. Never resend retained-read. A failed request may already have run.
- Concurrent m1mu2 readers: a nonblocking local lock admits one reader per
  session. This does not coordinate an independently running upstream client.
- Capture receipt collision, disk failure, or interrupted save: use exclusive
  file creation; never replace existing bytes. Orphan files may remain after an
  interrupted save; only a complete verified receipt is replayable.
- Offline replay rejects byte-count/hash/path mismatches. Its success proves
  saved bytes and provenance consistency, not live target health or identity.
- Tokens and connection secrets must never appear in stdout, receipts, or the
  journal. Only allowlisted metadata is persisted.

Verification runs the actual CLI in subprocesses against deterministic HTTP
and UNIX socket fixtures on loopback, exercises refusals before transport,
malformed/ambiguous replies, successful capture and offline replay, and writes
a receipt, command transcript, byte artifact, and hashes. All fixture evidence
is explicitly simulated, not hardware verification. The harness is rerunnable
and creates a fresh output directory for each run.

## REPL extension failure model (written before implementation)

- Terminal and piped input must select the same small command allowlist:
  status, captures, read/peek ADDRESS LENGTH, replay RECEIPT, help, and quit.
  Tokenization uses shlex only; Python evaluation, shell execution, arbitrary
  endpoint commands, writes, native calls, and per-command session replacement
  are not exposed. Malformed/unsafe input stops the REPL with a nonzero exit.
- The selected session, optional report, capture directory and live/dry-run
  setting are fixed at startup. A missing report blocks reads; it does not
  silently bind a different acquisition. Default read behavior stays dry-run.
- Every read reruns the existing identity, readiness, busy-state, prior-range,
  hash and no-retry checks. A failed read ends the REPL immediately, including
  for piped input, so later lines cannot repeat an ambiguous request.
- EOF/quit exit cleanly. Terminal interaction is verified through a real PTY;
  piped interaction is verified through actual CLI subprocess stdin/stdout.
- Upstream retained-bootstrap-move records started plus verified=true or
  missed=true without finished. Only that exact known command may use those
  explicit completion markers, and only when neither the operation nor the
  retained/control state is pending. Unknown unfinished operations still block.
- A successful upstream read appends a finished read operation and saved capture
  to its acquisition report. Snapshot checks must permit these expected report
  additions while continuing to reject changed identity, pending state or
  corruption count. Protocol fixtures reproduce these report updates.

## Existing application RPC probe (before implementation)

- A local bridge status response is not a console round trip. The separate
  `rpc-probe` command must query the application's existing SDK mapping and read
  exactly 32 bytes at recorded SDK + 0x4CC0, compared with the same-session
  verified-instructions signature. No arbitrary addresses, writes,
  native calls, bootstrap or acquisition are exposed. This does not qualify FS
  sysmodule reads or access to another game's files.
- Require the selected connection's session/platform, completed baseline and
  application qualification, restored scratch/import state, complete saved map,
  and an idle system-access state. A failed acquisition is acceptable only with
  recorded cleanup; an active or ambiguous acquisition is refused.
- Require the fixed window to lie in a saved RX code mapping with no IPC/device
  references or attributes. Compare fresh mapping queries before and after the
  read with that saved mapping. Reject wrong permissions, identity, byte count,
  malformed base64, or any metadata change. Snapshot checks cannot lock out
  independently running upstream clients.
- Dry-run must contact nothing. Live mode sends only status/query/read/query/status
  through the existing serialized local bridge, under the existing session lock.
  Any ambiguous failure stops immediately without retry. RPC scratch output may
  change internally; the source window and game/save data are never written.
- Persist a byte artifact and receipt only after all checks pass. Label it as
  application SDK RPC evidence, not retained-memory evidence. REPL rpc-probe
  uses the same startup live/dry setting and stops on failure. Verify actual CLI
  and REPL subprocess behavior with simulated bridge transcripts before hardware.
