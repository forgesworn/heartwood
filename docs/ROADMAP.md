# Heartwood ecosystem roadmap

One roadmap for the three repos: **heartwood** (bridge daemon + Pi appliance),
**heartwood-esp32** (device firmware, five boards), **sapwood** (web flasher +
admin console). Update this file as work lands; keep the session log brief.

Last updated: 2026-07-12.

## Where we are

Foundations are solid and verified: gated CI in all three repos (svelte-check +
vitest + Playwright in sapwood; five-board firmware build matrix + host crypto
tests in heartwood-esp32; fmt/clippy/test + multi-arch release in heartwood).
Firmware v0.9.14, sapwood v0.8.10 live at sapwood.forgesworn.dev, bridge
v0.7.0. Shipped and bench-proven: colour UI (T-Display + C6), concurrent
USB + Wi-Fi, relay-mediated management, on-device seed restore, ESP8266
tethered signer (built, not yet hardware-tested). What separates us from
world class is the prioritised list below.

## Priority 1 — Security audit + signed OTA

The remaining headline workstream from the world-class push ("100% safe" is
the number-one value). No hardware needed.

- [ ] Full-ecosystem security audit (all three repos). Key questions:
      operator key in localStorage vs XSS (adversarially test the CSP),
      relay management replay bounds, USB/frame parsing robustness,
      supply chain.
- [x] **Signed OTA** — BUILT 2026-07-02, compile-verified, all host tests
      green. ed25519 over the board-bound image digest
      (`common/src/ota_sign.rs`); enforced in `ota.rs` at OTA_BEGIN and
      OTA_FINISH; signed in `release.yml` by the new `ota-sign` tool with a
      sign-then-verify guard against key drift; signature carried by
      `version.json`/`.sig` assets through sapwood (`ota.ts`, legacy fallback
      for pre-signature firmware) and heartwoodd (`X-Firmware-Signature`).
      **SHIPPED in v0.10.0** (2026-07-02): release key generated and backed
      up, `OTA_SIGNING_SEED` secret set, release built green with all five
      images signed, sapwood serving the signed manifest (heltec-v4 image
      independently verified against the committed pubkey after sync).
      Remaining: one bench OTA on a Heltec — 0.9.x → 0.10.0 exercises the
      legacy fallback; the release after exercises enforcement. No eFuses
      involved; fully reversible. Runbook: heartwood-esp32
      `docs/ota-signing.md`.
- [ ] Reproducible firmware builds, so released binaries are verifiable
      against the tagged source. Pairs with signed OTA.
- [ ] Supply chain gates: `cargo-deny` in CI (heartwood #7, and
      heartwood-esp32), npm lockfile audit in sapwood CI.

## Priority 2 — Restore of the 12 words, done properly

Two complementary paths. On-device entry stays the gold standard (the phrase
never leaves the device — frame 0x58 sends only a label, never words); offline
USB is the accessible fallback for people who find button entry hard.

### On-device restore v2 — use the hardware we have

The current picker drives everything through button A tap/double-tap/hold —
the v0.9.1–0.9.4 gesture churn shows single-button entry is at its limit.
The board seam already exposes a second button (`board.rs::Hw.button_b`,
T-Display B = GPIO35) but the firmware never reads it (`main.rs` discards it
as `_button_b`).

- [ ] Two-button picker on the T-Display: A = advance/select (keep prefix
      autocomplete), B = back/delete. Removes the hold-timing gymnastics;
      overshoot becomes a single press, not a timed hold.
- [ ] Wire button B into approval flows too where present (A = approve,
      B = deny) — same win for everyday signing.
- [ ] Heltec/C6 single-button boards keep the current gesture picker
      (shipped, refined, works).
- [ ] C6: touch keyboard for word entry once the touch driver lands
      (priority 4) — the best restore experience of all the boards.
- Keep unchanged: BIP-39 checksum validation + npub confirm before store.

### Offline USB restore — secure and accessible

The air-gapped path already exists as the `provision` CLI (heartwood-esp32):
ESP32 + ESP8266 over USB, hidden interactive input, zeroised before the port
opens, on-device button hold to accept, npub read-back. Gaps are access and
verification, not design:

- [ ] Bench-verify the provision CLI against current ESP32 firmware on all
      boards (it is CI-covered on the host but part of the untested-on-
      hardware backlog).
- [ ] Generalise sapwood's offline-gated GUI provisioning (today only in the
      ESP8266 tethered wizard) to every board: restore-from-phrase and
      generate, gated behind the explicit "this computer is offline"
      acknowledgement with the live `navigator.onLine` warning and the key
      UI disabled until ticked. Same trust model as the CLI — clicks instead
      of commands.
- [ ] One short doc page: which restore path to use when. On-device = gold
      standard; offline USB (GUI or CLI) = fallback; a networked browser
      never sees the phrase.

## Priority 3 — Hardware verification debt

Shipped code that has never touched a real board. Needs the bench, not code.

- [ ] **ESP8266 first-flash pass** — `HARDWARE-TEST-CHECKLIST.md` §6. The
      boot POST is the gate: it recomputes frozen crypto vectors on the real
      lx106 in the first second. If it passes, the tethered tier is plumbing.
- [ ] Sapwood not-hardware-verified sweep: real-board flash from the live
      site under CSP, PhoneHandoff QR end-to-end, connect-an-app over a real
      relay and over USB.
- [ ] heartwood #8: device approval screen flashes too fast to read.

## Priority 4 — C6 touch (the product mission)

The 2026-07 mission is colour + touchscreen + USB + Wi-Fi. Colour is shipped
and bench-proven; touch is the missing piece.

- [ ] AXS5106L capacitive touch driver over I2C (Waveshare ESP32-C6
      Touch-LCD 1.47).
- [ ] Touch approve/deny for signing — a tap instead of a timed hold.
- [ ] Touch keyboard for restore (closes the loop with priority 2).
- QMI8658 IMU: later, maybe (wake-on-pickup).

## Priority 5 — PIN-derived seed encryption

The no-eFuse answer to device theft. Encrypt the seed at rest with a key
derived from a PIN/hold-sequence entered on-device at boot. Software-only,
reversible, no fuse burn. Design **after** the audit (priority 1) so it meets
the threat model the audit defines. Upgrades the device from shelf-HSM
towards something you could carry.

## Priority 6 — Hygiene burn-down

- [x] heartwood #4 (unauth API) + #5 (plaintext seed at rest) — **resolved by
      retiring the soft signer** (2026-07-02). Both findings lived only in
      `heartwood-device`, a key-holding Pi signer that contradicted
      "keys stay on hardware". Deleted it, its web UI, and the bunker sidecar;
      `heartwood-bridge` (keyless relay↔USB daemon) is now the whole product,
      configured from env/config.json + the `provision` CLI. Software-signer
      use case → lite.mysignet.app. Uncommitted; deployment pipeline
      (Docker/release) repointed but needs a real build/deploy test; README +
      architecture docs still need a positioning rewrite.
- [ ] Automate the sapwood firmware push to Hetzner: CI step fetching the
      firmware from the GitHub release by tag, replacing the manual rsync
      (the step that once served index.html as app.bin).
- [ ] Merge the two open dependabot PRs in sapwood.
- [ ] Keep lifting firmware logic into host-testable `common` (the pattern
      that caught the nonce and signing bugs) — the firmware crate itself has
      no unit tests and cannot, so `common` is where the coverage lives.
- [ ] heartwood #6 (typed NIP-46 params), #2 (`heartwood_switch` scope),
      #3 (`heartwood_capabilities`), #1 (connect/ping methods).

## Exploration track — Ledger port (working prototype, bench-gated)

`heartwood-ledger` (local repo, not yet on GitHub): the signer as a Ledger
embedded app, proven end-to-end in Speculos. Same seed phrase → same npub +
personas (frozen all-zero vector passes); `heartwood-common` compiles for the
Ledger target unmodified; chunked APDUs carry the exact 0x10 frame body.
Landed 2026-07-12: **TOFU signing approval** (first `sign_event` per client
blocks on an NBGL Approve/Reject; approved clients persist in app NVM and
sign unattended — e2e walks the buttons both ways), **cx-syscall signing**
(`cx_ecschnorr` BIP-0340, key zeroised after use), own icon, and the bridge's
**`ledger-tcp` transport** (this branch: `HEARTWOOD_TRANSPORT=ledger-tcp`,
no `bridge.secret`; live-smoked against Speculos with the real binary).

Also landed 2026-07-12 (later): **`ledger-hid` transport** (Ledger's 64-byte
report framing hand-rolled over Linux hidraw, zero new deps, framing
mock-tested; hardware end bench-gated), **`--bunker-uri`** (prints the
NIP-46 connection string per master, also logged at startup — the thing an
operator hands their Nostr client), and **`ledger-backend` in
heartwood-common** (heartwood-esp32 branch `ledger-backend`: pubkey, ECDH
with even-y lift via OS modular maths, and signing all on cx syscalls;
k256 fully out of the app; 163 host tests + cargo-deny green).

Remaining: bench test on a physical Nano S+ — sideload the app, rerun the
host driver over `ledger-hid` (needs the ~£70 device; the one place to
expect surprises is stack headroom), then the distribution decision
(sideload Nano S/S+ now; Ledger Live needs a paid third-party audit — the
Tezos baking app is the unattended-signing precedent). Also pending: a
GitHub home for `heartwood-ledger`, and merging the two feature branches.

## Non-goals / locked decisions

- **No eFuses, ever** — no secure boot, flash encryption, or NVS encryption.
  Brick risk is not accepted. Mitigations are operational plus priority 5.
- **ESP8266 is not an on-device vault** — no trustworthy TRNG and DRAM cannot
  hold the BIP-39 wordlist alongside the signing heap (both proven). Keys are
  provisioned offline; do not re-attempt on-device generate/restore there.
- **No i18n** — single-language British English, by design.
- The audience bar stands: one obvious action, no jargon, no dead ends —
  usable by an impatient kid and a non-technical adult, verified at 390px.

## Session log

- **2026-07-12** — Ledger port finished to emulator-proven: TOFU approval on
  Ledger buttons (NVM-persisted, e2e-driven via Speculos's REST API, approve
  AND reject paths), signing moved onto the `cx_ecschnorr` syscall, own icon,
  and `heartwood-bridge` gained a `ledger-tcp` transport (branch
  `ledger-transport`, zero new deps, 49 tests green, live-smoked against
  Speculos). Left: physical Nano S+ bench, HID transport, common's
  `ledger-backend`.
- **2026-07-11** — Ledger port researched, built and proven in one session.
  Feasibility verified (BOLOS has BIP-340/ECDH/ChaCha20; derivation path is
  plain BIP-32 so identities interoperate), then `heartwood-ledger` PoC built:
  Nano S+ app reusing `heartwood-common`, `scripts/e2e.sh` green — frozen
  vector npub match, NIP-46/NIP-44 round trips, persona derive/switch/sign
  all verified in Speculos. See the exploration track above for what remains.
- **2026-07-02 (later)** — Signed OTA implemented AND shipped as firmware
  v0.10.0 (see the P1 tick above for the pieces). Devices running 0.10.0+
  refuse firmware that isn't signed by the release key; a compromised
  update channel can no longer install code. Key generated + backed up,
  secret set, release green, sapwood synced and deployed. Left: one bench
  OTA on a Heltec.
- **2026-07-02** — Roadmap created from a three-repo survey (sapwood
  v0.8.10, firmware v0.9.14, bridge v0.7.0; all CI green, no open firmware
  issues, 8 open bridge issues). Decided: security audit + signed OTA first;
  restore v2 uses the T-Display's idle button B plus a generalised
  offline-USB path; PIN-derived seed encryption is the eFuse-free theft
  mitigation, designed post-audit.
