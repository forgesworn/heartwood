# Relay-to-serial signing bridge (`heartwood-bridge`)

**Status:** Implemented (crate builds, unit-tested); not yet exercised against hardware.
**Date:** 2026-06-25
**Crate:** `crates/heartwood-bridge`

## What this fills

The architecture has long listed an **HSM operational mode** — *"no master secret on the
Pi; NIP-46 requests are forwarded to an ESP32 hardware security module over a serial
port."* In practice only the **management** half existed (`/api/hsm/pin`, `/api/hsm/detect`
in `heartwood-device`): the Pi could set a PIN or detect a device, but **nothing carried
signing traffic between the relays and the device.** The relay-facing component, the Node
`bunker/` sidecar, is a *software* signer (`finalizeEvent(template, sk)`); it holds an nsec
and has no serial path. So HSM mode could be configured but could not actually sign.

`heartwood-bridge` is the missing data plane: a sidecar daemon that connects the Nostr
relays to a USB-tethered signing device. It is the device's network. This is what lets a
**Wi-Fi-less signer (e.g. an ESP8266, or an ESP32 with its radio deliberately off)**
participate in the relay-mediated ecosystem — the daemon listens to relays on its behalf
and pumps requests over USB.

## Why the bridge is *thin*

The firmware does all the cryptography **inline on the device**
(`heartwood-esp32 firmware/src/transport.rs::handle_encrypted_request`). On one
`ENCRYPTED_REQUEST` frame the device:

1. NIP-44-decrypts the request (master secret × client pubkey conversation key),
2. handles the NIP-46 method (sign_event, get_public_key, nip44_*, derive, …),
3. re-encrypts the response,
4. builds **and signs** the kind:24133 response envelope,
5. returns a fully-serialised signed event, *"ready to publish to relays verbatim."*

It is built this way on purpose — an earlier multi-round-trip design (send the response
back to the device just to sign the envelope) sent ~7 KB over serial and *"caused silent
ESP32 reboots."*

So the bridge **never holds key material and never sees plaintext.** It is a pump:

```
relay  ──kind:24133 request──►  bridge  ──0x10 ENCRYPTED_REQUEST──►  device
relay  ◄──signed response─────  bridge  ◄──0x35 SIGN_ENVELOPE_RESP─  device
```

## The serial contract

All frames are `[magic "HW"][type u8][len u16-be][payload][crc32-be]`. **The CRC covers
`type + len + payload`, NOT the magic** (see the bug note below). Frame types are a subset
of `heartwood-esp32 common/src/types.rs`.

| Step | Host → device | Device → host |
|------|---------------|----------------|
| Authenticate the bridge session | `SESSION_AUTH (0x21)` + 32-byte secret | `SESSION_ACK (0x22)` `[0x00]` ok / `[0x01]` wrong / `[0x02]` none |
| Discover masters | `PROVISION_LIST (0x05)` | `0x07` JSON `[{slot,label,mode,npub}]` |
| (Optional) sanity check | `FIRMWARE_INFO (0x59)` | `0x5A` `{version,board}` |
| Sign a request | `ENCRYPTED_REQUEST (0x10)` payload below | `SIGN_ENVELOPE_RESPONSE (0x35)` signed event JSON, or `NACK (0x15)` |

`0x10` payload: `[master_pk 32][client_pk 32][created_at u64-be 8][ciphertext bytes…]`

- `master_pk` — the request event's `p` tag (one of our masters); the device only uses it
  as a lookup key, never trusting it for the event's author field.
- `client_pk` — the request event author.
- `created_at` — **the bridge supplies the current unix time**, which the device writes
  into the response envelope. The device has no reliable clock; that is *why* the host
  passes it.
- `ciphertext` — the request event's `content` (a NIP-44 base64 string) forwarded verbatim.

`ENCRYPTED_REQUEST` is gated on a successful `SESSION_AUTH`. `SIGN_ENVELOPE (0x34)` is
**deprecated** in the firmware ("envelope signing is now inline") and is not used.

## Process shape

```
                       ┌───────────── tokio async ─────────────┐
 relay A ⇄ ws ─┐       │  relay task A ─┐                       │
 relay B ⇄ ws ─┼───────┼─ relay task B ─┼─ mpsc(jobs) ─►        │
 relay C ⇄ ws ─┘       │  relay task C ─┘             ┌─────────▼──────────┐ blocking thread
                       │      ▲                       │   serial worker    │ owns the port
                       │      └── broadcast(signed) ──┤  0x10 → 0x35 (seq)  │ ⇄ USB ⇄ device
                       └───────────────────────────── └────────────────────┘
```

- **One serial worker thread** owns the port (serial I/O is blocking). It authenticates,
  discovers masters (reported back via a `oneshot` so the relay tasks can build filters),
  then processes jobs **strictly sequentially** — the device answers one request at a time,
  and a sign may block up to ~45 s on a physical button press (TOFU "ask" policy). On any
  serial error it reopens and re-authenticates with backoff, retrying forever.
- **One async task per relay** subscribes `["REQ", …, {kinds:[24133], "#p":[masters], since:now}]`,
  forwards **de-duplicated** request events (the same request arrives from several relays;
  a bounded seen-set ensures we sign once), and publishes every signed response to **all**
  relays. Reconnects with capped backoff.
- Relay client is raw `tokio-tungstenite` + `serde_json` (no `nostr-sdk`), so the device's
  signed event is republished **byte-for-byte** and the dependency surface stays small.

## Configuration

Read from the shared instance dir (`HEARTWOOD_DATA_DIR`, default `/var/lib/heartwood/<i>`):

| Source | Field | Use |
|--------|-------|-----|
| `master.payload` | `hsm:<serial_port>` | the device's serial port (HSM mode marker; no key) |
| `config.json` | `relays` | relay list (falls back to the Pi defaults) |
| `bridge.secret` | 64-hex or 32 raw bytes | the serial bridge-session secret, shared with the device's NVS |

## Security model

- **No key, no plaintext on the host.** The bridge forwards ciphertext and republishes a
  signed event. Confidentiality and authority live on the device.
- **`bridge.secret`** authenticates the serial session (constant-time compared in firmware;
  setting it on the device needs a physical button hold). It is *not* the signing key — it
  authorises the USB pump, nothing more. Treat the file as a local secret (mode 0600).
- **Replay / policy** are the device's job: it enforces NIP-44 integrity, kind allowlists,
  rate limits and per-client TOFU policy, and NACKs anything it dislikes. The bridge only
  de-duplicates request ids to avoid double-submitting the same event.
- **What a relay sees:** the same metadata NIP-46 already exposes (a master pubkey is
  online, request/response timing). No new secret leakage.
- **NIP-42 AUTH is unsupported.** The bridge holds no key, so it cannot sign an auth
  challenge. Relays that require AUTH for kind-24133 are out of scope; use open relays for
  the tethered tier (or the device-direct Wi-Fi-standalone tier where the device signs its
  own AUTH).

## Deployment

`boards/pi/heartwood-bridge@.service` — a sidecar template unit mirroring
`heartwood-bunker@.service`, plus serial access (`SupplementaryGroups=dialout`,
`DeviceAllow=char-ttyUSB/ttyACM rw`). It is the HSM-mode counterpart of the bunker: in
non-HSM modes the Node bunker signs; in HSM mode the bridge pumps to the device. They are
mutually exclusive by mode.

## Fixed — `heartwood-device` web serial CRC

While matching the firmware's wire format I found that `heartwood-device/src/web.rs`'s
private `build_frame`/`read_frame` computed the CRC over **`crc32fast::hash(&frame)`** —
i.e. **including the magic bytes** — whereas the firmware
(`heartwood-esp32 common/src/frame.rs`) hashes **`type + len + payload` only**. They
disagreed, so the existing `/api/hsm/pin` (`SET_PIN`) path was **wire-incompatible with the
device** and would fail CRC. It had likely never been exercised against hardware (HSM
signing did not exist until now). **Fixed** in this change (both sites now hash from
`FRAME_MAGIC.len()`, matching the firmware). The proper long-term fix is to share one
codec (a future `heartwood-frame` crate) so `web.rs` and the bridge cannot drift again.

## Status & follow-ups

- ✅ Crate builds; 20 tests pass — 19 unit (frame round-trip + firmware-parity CRC, npub
  decode vs the NIP-19 vector, request parsing, `0x10` payload layout, dedup, secret
  parsing) plus a hardware-free **end-to-end** test driving the real relay client and the
  real `SerialSession` over a socket pair + a local websocket relay against a device
  simulator (relay → `0x10` → simulated device → `0x35` → relay), verified stable over
  repeated runs.
- ⏳ **Hardware bring-up** — run against a provisioned ESP32 (set a `bridge.secret`, plug
  in, sign from a NIP-46 client). Not yet done.
- ⏳ **Provisioning UX** — where the operator sets `bridge.secret` on *both* the device
  (`SET_BRIDGE_SECRET 0x23`, with button) and the Pi (`bridge.secret` file). Today it must
  be placed by hand; Sapwood/the web setup should write both.
- ✅ **`web.rs` CRC fixed** (above); the shared-frame-crate refactor remains a follow-up.
- ⏳ **ESP8266 firmware** — the device half for a truly Wi-Fi-less signer. The spike proved
  the crypto fits; a `no_std` UART + frame + inline-sign firmware is a separate build, and
  the inline NIP-44 + JSON path needs an on-8266 RAM check.
