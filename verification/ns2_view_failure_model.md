# Passive Switch capture viewer failure model

Before implementation, the end-to-end checks must cover:

- A running or failed acquisition must not be labeled connected/ready.
- Saved memory bytes must never be labeled live data or game assets.
- A missing, partial, stale, outside-session, or hash-mismatched capture must not be previewed or downloaded as verified data.
- Requesting an arbitrary path or an unknown capture ID must fail.
- Device operations must be impossible through the viewer: it exposes local evidence GET requests only, with no endpoint connection or live-read command.
- Another site must not use a rebinding Host header to read local evidence; bind loopback and validate the exact Host.
- Values from reports and capture names must render as text, never executable markup.
- Preview size is bounded; downloads recheck the whole capture against its digest.
- E2E artifacts must identify synthetic fixtures separately from an actual local session status observation. No fixture establishes hardware access.
