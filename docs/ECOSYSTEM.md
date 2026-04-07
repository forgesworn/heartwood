# The ForgeSworn Identity Stack

Your keys never leave the device.

The ForgeSworn identity stack is a set of open source tools that move Nostr key management off your laptop and onto dedicated hardware. One mnemonic seed generates unlimited unlinkable identities, signed on a device you control, accessible from any browser through standard APIs.

```mermaid
graph TB
    subgraph External["External"]
        WA["Any Nostr App"]
        AG["Nostr Agents<br/>(bray, Amethyst, etc.)"]
        Relay["Nostr Relays"]
    end

    subgraph ClientLayer["Client Tools"]
        Bark["Bark Extension"]
        Sapwood["Sapwood Manager"]
    end

    subgraph DeviceLayer["Signing Device"]
        HW["Heartwood<br/>Raspberry Pi Zero 2 W"]
        ESP["ESP32 HSM<br/>(optional)"]
    end

    subgraph CryptoLayer["Crypto Foundation"]
        NT["nsec-tree<br/>(key derivation)"]
    end

    WA -->|"window.nostr"| Bark
    Bark -->|"NIP-46"| Relay
    AG -->|"NIP-46<br/>(bunker URI)"| Relay
    Relay -->|"NIP-46"| HW
    Sapwood -->|"Web Serial / HTTP"| HW
    HW <-->|"Serial frames"| ESP
    HW -.->|"key derivation"| NT

    style Bark fill:#3b82f6,color:#fff
    style Sapwood fill:#3b82f6,color:#fff
    style AG fill:#3b82f6,color:#fff
    style HW fill:#f59e0b,color:#000
    style ESP fill:#ef4444,color:#fff
    style NT fill:#1e293b,color:#e2e8f0
    style Relay fill:#8b5cf6,color:#fff
```

**Bark** is a browser extension that provides the standard `window.nostr` API (NIP-07). It holds no keys. Every signing request is forwarded over NIP-46 to your Heartwood device. Bark is one way in -- any NIP-46 client (bray, Amethyst, or any agent with a bunker URI) can connect directly to Heartwood via relay without Bark.

**Heartwood** is a dedicated signing appliance running on a Raspberry Pi Zero 2 W. It stores your master secret (encrypted at rest with AES-256-GCM + Argon2id), derives child identities using nsec-tree's HMAC-SHA256 scheme, and signs events with BIP-340 Schnorr. Accessible over Tor.

**Sapwood** is a browser-based management UI for provisioning, policy management, and firmware updates. Connects via Web Serial (USB) or HTTP (bridge on the Pi). 21 KB gzipped.

**ESP32 HSM** is an optional hardware security module. In HSM mode, the Pi stores nothing and forwards signing requests to the ESP32 over serial. Provisioning and factory reset require a physical button press.

**nsec-tree** is the cryptographic foundation. A deterministic key derivation library that creates unlimited child identities from a single seed using HMAC-SHA256. Implemented in TypeScript (npm) and Rust (heartwood-core).

---

## Setting up for the first time

Provisioning a Heartwood device takes about five minutes. You generate or import a master identity, derive personas for different contexts, and connect Bark.

```mermaid
sequenceDiagram
    participant U as User
    participant S as Sapwood
    participant HW as Heartwood
    participant B as Bark
    participant WA as Web App

    U->>S: Connect via USB or HTTP
    S->>HW: Provision master identity
    Note over HW: Encrypt and store root secret
    HW-->>S: ACK

    U->>HW: Derive personas via web UI
    Note over HW: personal, work, bitcoiner...

    U->>B: Install extension, enter bunker URI
    B->>HW: NIP-46 connect (via relay)
    HW-->>B: Connected

    U->>WA: Browse to any Nostr app
    WA->>B: window.nostr detected
    Note over U,WA: Ready to sign
```

Three provisioning modes are available:

| Mode | Input | Key storage | Use case |
|------|-------|-------------|----------|
| **Tree (mnemonic)** | 12/24-word BIP-39 seed | Derived root on device | New master identity from scratch |
| **Tree (nsec)** | Existing nsec | HMAC-derived root on device | Existing Nostr identity |
| **HSM** | Mnemonic or nsec via Sapwood | Secret on ESP32 only | Maximum isolation |

In all modes, the private key never touches a general-purpose computer.

---

## Signing an event

When a web app calls `window.nostr.signEvent()`, the request travels through Bark's message chain, across a Nostr relay, into Heartwood, and back with a signature. The private key never leaves the device.

```mermaid
sequenceDiagram
    participant WA as Web App
    participant P as provider.js
    participant CS as content-script.js
    participant BG as background.js
    participant R as Nostr Relay
    participant HW as Heartwood

    WA->>P: signEvent(event)
    P->>CS: postMessage
    CS->>BG: chrome.runtime.sendMessage

    Note over BG: Policy check (allow / ask / deny)
    alt Policy requires approval
        BG->>BG: Show approval popup
        Note over BG: User approves
    end

    BG->>R: NIP-46 sign_event (NIP-44 encrypted)
    R->>HW: Forward request

    Note over HW: Permission check, rate limit
    Note over HW: Resolve active identity
    Note over HW: BIP-340 Schnorr sign

    HW->>R: NIP-46 response (NIP-44 encrypted)
    R->>BG: Forward response
    BG->>CS: Response
    CS->>P: postMessage
    P->>WA: Signed event
```

All relay traffic is NIP-44 encrypted (XChaCha20 + HMAC-SHA256). Heartwood enforces per-client permissions (kind allowlists, method restrictions) and rate limits (60 requests/minute). Requests have a 60-second timeout to allow for physical approval on hardware devices.

The nsec is never included in any response. Only signatures and public keys leave the device.

---

## Where do secrets live?

The most important question for any signing architecture: where is the key material?

### Software mode (Raspberry Pi only)

The master secret is encrypted at rest on the Pi's SD card. It's only decrypted into memory when the device is unlocked with a PIN.

```mermaid
graph TB
    M["Mnemonic or nsec"] -->|"nsec-tree derivation"| TR["Tree Root (32 bytes)"]
    TR -->|"AES-256-GCM + Argon2id"| EF["Encrypted file on SD card"]
    PIN["PIN unlock"] -->|"Decrypt to memory"| MEM["Secret in memory"]
    MEM -->|"Sign events"| SIG["Signatures out"]
    MEM -->|"Lock / shutdown"| Z["Zeroised"]
    EF -.->|"On unlock"| MEM

    style M fill:#1e293b,color:#e2e8f0
    style TR fill:#1e293b,color:#e2e8f0
    style EF fill:#f59e0b,color:#000
    style PIN fill:#3b82f6,color:#fff
    style MEM fill:#ef4444,color:#fff
    style SIG fill:#16c79a,color:#000
    style Z fill:#ef4444,color:#fff
```

All secrets in memory are wrapped in zeroising containers and overwritten on lock or shutdown.

### HSM mode (Raspberry Pi + ESP32)

The Pi stores nothing. The ESP32 holds the master secret in its non-volatile storage. The Pi acts as a network proxy, forwarding NIP-46 requests to the ESP32 over serial.

```mermaid
graph TB
    M["Mnemonic or nsec"] -->|"Sapwood provisions via USB"| ESP["ESP32 NVS storage"]
    HW["Heartwood on RPi"] -->|"Serial frame"| ESP
    ESP -->|"Signs locally"| SIG["Signature returned to RPi"]
    BTN["Physical button"] -.->|"Required for"| PROV["Provision / Reset / OTA"]

    style M fill:#1e293b,color:#e2e8f0
    style ESP fill:#ef4444,color:#fff
    style HW fill:#f59e0b,color:#000
    style SIG fill:#16c79a,color:#000
    style BTN fill:#ef4444,color:#fff
```

Compromising the Pi in HSM mode yields zero key material. The ESP32 requires a physical button press for all destructive operations (provisioning, factory reset, firmware update).

---

## One seed, many identities

A single mnemonic generates an unlimited tree of unlinkable Nostr identities using nsec-tree's HMAC-SHA256 derivation. Each persona appears as an independent keypair to outside observers.

```mermaid
graph TB
    SEED["Master Seed"] --> P1["Persona: personal"]
    SEED --> P2["Persona: work"]
    SEED --> P3["Persona: bitcoiner"]

    P1 --> G1["Group: family-chat"]
    P1 --> G2["Group: close-friends"]
    P2 --> G3["Group: company:acme"]

    style SEED fill:#ef4444,color:#fff
    style P1 fill:#f59e0b,color:#000
    style P2 fill:#f59e0b,color:#000
    style P3 fill:#f59e0b,color:#000
    style G1 fill:#3b82f6,color:#fff
    style G2 fill:#3b82f6,color:#fff
    style G3 fill:#3b82f6,color:#fff
```

**Unlinkable by default.** No observer can prove two personas share a master without a linkage proof. Derivation is one-way (HMAC-SHA256), so compromising a child reveals nothing about the parent or siblings.

**Selective disclosure.** When you want to prove ownership across personas, nsec-tree creates BIP-340 Schnorr linkage proofs. Blind proofs hide the derivation path. Full proofs reveal it. You choose.

**Compromise blast radius:**

| Compromised | Blast radius | Recovery |
|-------------|--------------|----------|
| Group key | Only that group | Rotate to new index |
| Persona key | That persona and its groups | New persona index, publish blind proof |
| Master seed | Everything | New mnemonic, migrate all identities |

Bark's popup UI lets you switch between personas and derive new ones without leaving the browser. The active identity is managed by Heartwood, so switching is instant and consistent across all connected apps.

---

## Components

| Component | Role | Language | Architecture |
|-----------|------|----------|--------------|
| [Heartwood](https://github.com/forgesworn/heartwood) | Dedicated signing device | Rust | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| [Bark](https://github.com/forgesworn/bark) | Browser extension (NIP-07) | JavaScript | [ARCHITECTURE.md](https://github.com/forgesworn/bark/blob/main/ARCHITECTURE.md) |
| [Sapwood](https://github.com/forgesworn/sapwood) | Device management UI | TypeScript / Svelte | [ARCHITECTURE.md](https://github.com/forgesworn/sapwood/blob/main/ARCHITECTURE.md) |
| [nsec-tree](https://github.com/forgesworn/nsec-tree) | Key derivation library | TypeScript | [ARCHITECTURE.md](https://github.com/forgesworn/nsec-tree/blob/main/ARCHITECTURE.md) |

**Ecosystem-adjacent libraries** that build on nsec-tree:
- [canary-kit](https://github.com/forgesworn/canary-kit) -- duress-resistant verification using nsec-tree group keys
- [spoken-token](https://github.com/forgesworn/spoken-token) -- voice verification tokens bound to persona pubkeys
