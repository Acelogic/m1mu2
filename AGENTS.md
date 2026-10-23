# Project instructions

- Use Context Mode for source exploration and large outputs when available.
- Preserve unrelated work, captures, credentials, and the vendored `pokeldn-src` tree.
- Keep target-specific transports separate. Importing the Switch backend must not load the FireRed host stack or touch its radio.
- Switch operations inspect existing qualified sessions only. Never silently start acquisition, pair, bootstrap, install, execute code, write memory, or borrow another tool's connection.
- Pin retained reads to the explicitly selected session and acquisition report. The fixed application RPC probe instead requires that session's completed application qualification, saved map and instruction signature, plus confirmed acquisition cleanup. Reject stale, unqualified, retired, pending, or actively acquiring state. Validate lengths, hashes, and identity; never replay an ambiguous hardware request.
- Keep offline captures, protocol-fixture results, and physical hardware results clearly labeled. A fixture pass is not a successful console read.
- Never write unit tests after writing code.
- Highly prefer E2E tests as the sole testing mechanism for new complex features. Produce a verifiable, repeatable artifact after each E2E run.
- If testing a system in isolation is necessary, first write down the ways it could fail, then write the code.
- Delete a focused test only when an existing E2E test catches the same real failures. Do not remove coverage merely because it is called a unit test.
