# Multi-Instance Bunker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable multiple independent Heartwood bunker instances on a single device, each with its own mnemonic, client allowlist, and derived identity tree.

**Architecture:** Replace hardcoded `/var/lib/heartwood` paths with a `HEARTWOOD_DATA_DIR` env var in both the Node.js bunker and Rust device. Add `HEARTWOOD_AUTHORIZED_KEYS` env var support to the bunker. Create systemd template units (`heartwood@.service`, `heartwood-bunker@.service`) that parameterise the instance name. Add a standalone `derive-client-key.mjs` CLI tool for extracting persistent NIP-46 client keys from the nsec-tree.

**Tech Stack:** Rust (heartwood-device), Node.js/ES modules (bunker), systemd template units, nsec-tree (npm)

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `bunker/index.mjs` | Read `HEARTWOOD_DATA_DIR` env var for data path |
| Modify | `bunker/lib.mjs` | Add `resolveDataDir()` and `parseAuthorizedKeysEnv()` |
| Modify | `bunker/test/lib.test.mjs` | Tests for new lib functions |
| Modify | `crates/heartwood-device/src/main.rs` | Read `HEARTWOOD_DATA_DIR` env var, pass to Storage and AuditLog |
| Modify | `crates/heartwood-device/src/web.rs` | Replace hardcoded paths with `data_dir` from AppState |
| Modify | `crates/heartwood-device/src/tor.rs` | Accept data dir in `TorManager::new()` |
| Create | `tools/derive-client-key.mjs` | Standalone CLI for extracting client keys from nsec-tree |
| Create | `tools/package.json` | Dependencies for derive-client-key (nsec-tree, nostr-tools) |
| Create | `pi/heartwood@.service` | Systemd template unit for Rust device |
| Create | `pi/heartwood-bunker@.service` | Systemd template unit for Node.js bunker |
| Modify | `pi/setup.sh` | Rewrite for multi-instance setup |

---

### Task 1: Add `resolveDataDir` and `parseAuthorizedKeysEnv` to bunker/lib.mjs

**Files:**
- Modify: `bunker/lib.mjs`
- Modify: `bunker/test/lib.test.mjs`

- [ ] **Step 1: Write failing tests for `resolveDataDir`**

Add to `bunker/test/lib.test.mjs`:

```javascript
import {
  parseAuthorizedKeys,
  isApproved,
  isKindAllowed,
  recordPending,
  tryAutoApprove,
  checkRateLimit,
  resolveDataDir,
  parseAuthorizedKeysEnv,
} from '../lib.mjs'

// ... existing tests ...

// ---------- resolveDataDir ----------

describe('resolveDataDir', () => {
  it('returns env var value when set', () => {
    assert.equal(resolveDataDir({ HEARTWOOD_DATA_DIR: '/data/personal' }), '/data/personal')
  })

  it('returns default when env var is missing', () => {
    assert.equal(resolveDataDir({}), '/var/lib/heartwood')
  })

  it('returns default when env var is empty string', () => {
    assert.equal(resolveDataDir({ HEARTWOOD_DATA_DIR: '' }), '/var/lib/heartwood')
  })

  it('strips trailing slash', () => {
    assert.equal(resolveDataDir({ HEARTWOOD_DATA_DIR: '/data/personal/' }), '/data/personal')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd bunker && npm test`
Expected: FAIL — `resolveDataDir` is not exported from `lib.mjs`

- [ ] **Step 3: Implement `resolveDataDir`**

Add to `bunker/lib.mjs` at the end of the file:

```javascript
const DEFAULT_DATA_DIR = '/var/lib/heartwood'

/**
 * Resolve the data directory from environment variables.
 * @param {Record<string, string>} env - process.env or equivalent
 * @returns {string}
 */
export function resolveDataDir(env) {
  const dir = env.HEARTWOOD_DATA_DIR
  if (!dir) return DEFAULT_DATA_DIR
  return dir.endsWith('/') ? dir.slice(0, -1) : dir
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd bunker && npm test`
Expected: All `resolveDataDir` tests PASS

- [ ] **Step 5: Write failing tests for `parseAuthorizedKeysEnv`**

Add to `bunker/test/lib.test.mjs`:

```javascript
// ---------- parseAuthorizedKeysEnv ----------

describe('parseAuthorizedKeysEnv', () => {
  it('returns empty set when env var is missing', () => {
    const { keys, warnings } = parseAuthorizedKeysEnv({})
    assert.equal(keys.size, 0)
    assert.equal(warnings.length, 0)
  })

  it('parses comma-separated hex keys from env', () => {
    const { keys } = parseAuthorizedKeysEnv({ HEARTWOOD_AUTHORIZED_KEYS: `${PK_A},${PK_B}` })
    assert.equal(keys.size, 2)
    assert.ok(keys.has(PK_A))
    assert.ok(keys.has(PK_B))
  })

  it('warns on invalid keys in env', () => {
    const { keys, warnings } = parseAuthorizedKeysEnv({ HEARTWOOD_AUTHORIZED_KEYS: `${PK_A},bad` })
    assert.equal(keys.size, 1)
    assert.deepEqual(warnings, ['bad'])
  })

  it('returns empty set when env var is empty string', () => {
    const { keys } = parseAuthorizedKeysEnv({ HEARTWOOD_AUTHORIZED_KEYS: '' })
    assert.equal(keys.size, 0)
  })
})
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd bunker && npm test`
Expected: FAIL — `parseAuthorizedKeysEnv` is not exported

- [ ] **Step 7: Implement `parseAuthorizedKeysEnv`**

Add to `bunker/lib.mjs`:

```javascript
/**
 * Parse authorized keys from the HEARTWOOD_AUTHORIZED_KEYS env var.
 * Same format as --authorized-keys CLI flag (comma-separated hex pubkeys).
 * @param {Record<string, string>} env - process.env or equivalent
 * @returns {{ keys: Set<string>, warnings: string[] }}
 */
export function parseAuthorizedKeysEnv(env) {
  const raw = env.HEARTWOOD_AUTHORIZED_KEYS
  if (!raw) return { keys: new Set(), warnings: [] }

  const keys = new Set()
  const warnings = []
  for (const k of raw.split(',')) {
    const hex = k.trim()
    if (/^[0-9a-f]{64}$/.test(hex)) {
      keys.add(hex)
    } else if (hex.length > 0) {
      warnings.push(hex)
    }
  }
  return { keys, warnings }
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd bunker && npm test`
Expected: All tests PASS (48 existing + 8 new = 56)

- [ ] **Step 9: Commit**

```bash
git add bunker/lib.mjs bunker/test/lib.test.mjs
git commit -m "feat: add resolveDataDir and parseAuthorizedKeysEnv to bunker lib"
```

---

### Task 2: Wire `HEARTWOOD_DATA_DIR` and `HEARTWOOD_AUTHORIZED_KEYS` into bunker/index.mjs

**Files:**
- Modify: `bunker/index.mjs`

- [ ] **Step 1: Replace hardcoded `DATA_DIR` with `resolveDataDir`**

In `bunker/index.mjs`, change the import to include `resolveDataDir` and `parseAuthorizedKeysEnv`:

```javascript
import {
  parseAuthorizedKeys,
  parseAuthorizedKeysEnv,
  isApproved,
  isKindAllowed,
  recordPending,
  tryAutoApprove,
  checkRateLimit,
  resolveDataDir,
} from './lib.mjs'
```

Replace:

```javascript
const DATA_DIR = '/var/lib/heartwood'
```

With:

```javascript
const DATA_DIR = resolveDataDir(process.env)
```

- [ ] **Step 2: Merge env var authorized keys with CLI flag**

Replace the authorized keys section:

```javascript
// --- 0. Parse CLI flags and env vars ---

const { keys: cliKeys, warnings: cliWarnings } = parseAuthorizedKeys(process.argv)
const { keys: envKeys, warnings: envWarnings } = parseAuthorizedKeysEnv(process.env)

// CLI keys take precedence: if --authorized-keys is provided, use only those.
// Otherwise fall back to HEARTWOOD_AUTHORIZED_KEYS env var.
const authorizedKeys = cliKeys.size > 0 ? cliKeys : envKeys
const akWarnings = cliKeys.size > 0 ? cliWarnings : envWarnings

for (const w of akWarnings) {
  console.warn(`WARN: ignoring invalid authorized key: ${w}`)
}
if (authorizedKeys.size > 0) {
  console.log(`Authorized keys: ${authorizedKeys.size} client(s) will be auto-approved`)
}
```

- [ ] **Step 3: Syntax check**

Run: `node --check bunker/index.mjs`
Expected: Exit 0 (no syntax errors)

- [ ] **Step 4: Run existing tests to verify no regressions**

Run: `cd bunker && npm test`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add bunker/index.mjs
git commit -m "feat: bunker reads HEARTWOOD_DATA_DIR and HEARTWOOD_AUTHORIZED_KEYS env vars"
```

---

### Task 3: Add `HEARTWOOD_DATA_DIR` support to Rust device

**Files:**
- Modify: `crates/heartwood-device/src/main.rs`
- Modify: `crates/heartwood-device/src/web.rs`
- Modify: `crates/heartwood-device/src/tor.rs`

- [ ] **Step 1: Read env var in main.rs and pass to all components**

Replace the current `main.rs` construction of storage, audit_log, and oled with:

```rust
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Heartwood starting...");

    let data_dir = std::env::var("HEARTWOOD_DATA_DIR")
        .unwrap_or_else(|_| "/var/lib/heartwood".to_string());
    let data_path = std::path::PathBuf::from(&data_dir);
    info!("Data directory: {}", data_dir);

    let oled = oled::Oled::new();
    let storage = storage::Storage::new(Some(data_path.clone()));
    let audit_log = audit::AuditLog::with_persistence(data_path.join("audit.log"));

    oled.show_text("HEARTWOOD");

    if !storage.has_master_secret() {
        oled.show_text("SETUP MODE");
        info!("No master secret found. Entering setup mode.");
    } else {
        info!("Master secret stored. Device locked until PIN is entered.");
        oled.show_text("LOCKED");
    }

    let state = Arc::new(web::AppState {
        audit_log: Mutex::new(audit_log),
        storage: Mutex::new(storage),
        decrypted_payload: Mutex::new(None),
        unlock_throttle: Mutex::new(web::UnlockThrottle::new()),
        data_dir: data_path,
    });
    let app = web::create_router(state);

    let bind_addr = std::env::var("HEARTWOOD_BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind {bind_addr}: {e}");
            std::process::exit(1);
        }
    };
    info!("Web UI listening on {bind_addr}");
    oled.show_text("READY");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {e}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 2: Add `data_dir` field to `AppState` in web.rs**

In `crates/heartwood-device/src/web.rs`, add the field to `AppState`:

```rust
pub struct AppState {
    pub audit_log: Mutex<AuditLog>,
    pub storage: Mutex<Storage>,
    pub decrypted_payload: Mutex<Option<String>>,
    pub unlock_throttle: Mutex<UnlockThrottle>,
    pub data_dir: std::path::PathBuf,
}
```

- [ ] **Step 3: Add a helper method to AppState for building file paths**

Add after the `AppState` struct definition:

```rust
impl AppState {
    /// Build a path to a file in the instance data directory.
    fn data_file(&self, name: &str) -> String {
        self.data_dir.join(name).to_string_lossy().to_string()
    }
}
```

- [ ] **Step 4: Replace all hardcoded paths in web.rs**

Replace every `/var/lib/heartwood/<filename>` string literal with `state.data_file("<filename>")`. There are ~16 occurrences. Key replacements:

In `rewrite_bunker_uri`:
```rust
fn rewrite_bunker_uri(relays: &[String], data_dir: &std::path::Path) {
    let bunker_uri_path = data_dir.join("bunker-uri.txt");
    let bunker_uri_str = bunker_uri_path.to_string_lossy();
    // ... rest of function uses bunker_uri_path instead of BUNKER_URI_PATH const
```

The `rewrite_bunker_uri` function doesn't have access to `State` — it's called from a handler. Add `data_dir: &std::path::Path` as a parameter and pass `&state.data_dir` from the caller.

For each handler that reads/writes files, replace the hardcoded path with `state.data_file("filename")`. For example:

```rust
// Before:
let bunker_uri = std::fs::read_to_string("/var/lib/heartwood/bunker-uri.txt")

// After:
let bunker_uri = std::fs::read_to_string(state.data_file("bunker-uri.txt"))
```

Apply this pattern to all 16 occurrences:
- `bunker-uri.txt` (lines 191, 849, 908)
- `bunker-status.json` (line 919)
- `tor-hostname` (line 1042)
- `clients.json` (lines 1091, 1115, 1131, 1157, 1160, 1175)
- `pending-clients.json` (lines 1092, 1140, 1143, 1182)

- [ ] **Step 5: Update TorManager to accept data_dir**

In `crates/heartwood-device/src/tor.rs`, change `TorManager::new()` to accept a path:

```rust
impl TorManager {
    /// Create a manager using the given data directory for the hostname file.
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { onion_dir: data_dir }
    }
```

Update any callers of `TorManager::new()` to pass the data dir.

- [ ] **Step 6: Build and verify**

Run: `cargo build -p heartwood-device`
Expected: Compiles successfully

- [ ] **Step 7: Run tests**

Run: `cargo test`
Expected: All tests PASS (existing tests use `Storage::new(None)` which falls back to default — they still work)

- [ ] **Step 8: Commit**

```bash
git add crates/heartwood-device/
git commit -m "feat: heartwood-device reads HEARTWOOD_DATA_DIR env var"
```

---

### Task 4: Create derive-client-key CLI tool

**Files:**
- Create: `tools/derive-client-key.mjs`
- Create: `tools/package.json`

- [ ] **Step 1: Create tools/package.json**

```json
{
  "name": "heartwood-tools",
  "version": "0.1.0",
  "description": "Heartwood CLI utilities",
  "type": "module",
  "dependencies": {
    "nostr-tools": "^2.23.0",
    "nsec-tree": "^1.4.2"
  }
}
```

- [ ] **Step 2: Install dependencies**

Run: `cd tools && npm install`

- [ ] **Step 3: Create derive-client-key.mjs**

```javascript
#!/usr/bin/env node
/**
 * derive-client-key — extract a persistent NIP-46 client key from nsec-tree.
 *
 * Usage:
 *   node derive-client-key.mjs --nsec <nsec1...> --name <name>
 *   node derive-client-key.mjs --nsec <nsec1...> --name <name> --index <n>
 *
 * The derived private key is printed to stdout. Save it to a file for use
 * with Bray's --bunker-key-file flag. The corresponding pubkey goes into
 * the bunker's HEARTWOOD_AUTHORIZED_KEYS env var.
 *
 * This tool runs locally and never touches the network.
 */

import { decode as nip19decode } from 'nostr-tools/nip19'
import { bytesToHex } from 'nostr-tools/utils'
import { fromNsec } from 'nsec-tree/core'
import { derivePersona } from 'nsec-tree/persona'

function usage() {
  console.error('Usage: node derive-client-key.mjs --nsec <nsec1...> --name <name> [--index <n>]')
  console.error('')
  console.error('Options:')
  console.error('  --nsec <nsec1...>   Master nsec in bech32 format')
  console.error('  --name <name>       Persona name (e.g. client/bray, agent/dispatch)')
  console.error('  --index <n>         Derivation index (default: 0)')
  process.exit(1)
}

const args = process.argv.slice(2)

function getArg(flag) {
  const idx = args.indexOf(flag)
  if (idx === -1 || idx + 1 >= args.length) return undefined
  return args[idx + 1]
}

const nsec = getArg('--nsec')
const name = getArg('--name')
const index = parseInt(getArg('--index') ?? '0', 10)

if (!nsec || !name) usage()

// Decode nsec
let userSk
try {
  const decoded = nip19decode(nsec)
  if (decoded.type !== 'nsec') {
    console.error('ERROR: expected nsec, got ' + decoded.type)
    process.exit(1)
  }
  userSk = decoded.data
} catch (e) {
  console.error('ERROR: invalid nsec — ' + e.message)
  process.exit(1)
}

// Derive
const treeRoot = fromNsec(new Uint8Array(userSk))
let derived
try {
  derived = derivePersona(treeRoot, name, index)
} catch (e) {
  console.error('ERROR: derivation failed — ' + e.message)
  treeRoot.destroy()
  userSk.fill(0)
  process.exit(1)
}

const pubkey = bytesToHex(derived.identity.publicKey)
const secret = bytesToHex(derived.identity.privateKey)

console.log(`Name:    ${name}`)
console.log(`Index:   ${index}`)
console.log(`Purpose: ${derived.identity.purpose}`)
console.log(`Pubkey:  ${pubkey}`)
console.log(`Secret:  ${secret}`)

// Clean up
treeRoot.destroy()
userSk.fill(0)
derived.identity.privateKey.fill(0)
```

- [ ] **Step 4: Verify it runs with --help-like invocation**

Run: `node tools/derive-client-key.mjs`
Expected: Prints usage and exits with code 1

- [ ] **Step 5: Commit**

```bash
git add tools/
git commit -m "feat: add derive-client-key CLI tool for persistent NIP-46 client keys"
```

---

### Task 5: Create systemd template units

**Files:**
- Create: `pi/heartwood@.service`
- Create: `pi/heartwood-bunker@.service`

- [ ] **Step 1: Create heartwood@.service**

```ini
[Unit]
Description=Heartwood signing appliance (%i)
After=network-online.target
Wants=network-online.target
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
User=heartwood
Group=heartwood
ExecStart=/usr/local/bin/heartwood
Restart=always
RestartSec=10
Environment=RUST_LOG=info
Environment=HEARTWOOD_DATA_DIR=/var/lib/heartwood/%i

# Security hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/heartwood/%i
NoNewPrivileges=true
PrivateTmp=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
DevicePolicy=closed
DeviceAllow=/dev/i2c-1 rw

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create heartwood-bunker@.service**

```ini
[Unit]
Description=Heartwood NIP-46 bunker (%i)
After=network-online.target heartwood@%i.service
Wants=network-online.target
Requires=heartwood@%i.service
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
User=heartwood
Group=heartwood
WorkingDirectory=/opt/heartwood/bunker
ExecStart=/usr/bin/node index.mjs
Restart=always
RestartSec=15
Environment=NODE_ENV=production
Environment=HEARTWOOD_DATA_DIR=/var/lib/heartwood/%i

# Security hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/heartwood/%i
ReadOnlyPaths=/opt/heartwood
NoNewPrivileges=true
PrivateTmp=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Commit**

```bash
git add pi/heartwood@.service pi/heartwood-bunker@.service
git commit -m "feat: add systemd template units for multi-instance deployment"
```

---

### Task 6: Rewrite pi/setup.sh for multi-instance

**Files:**
- Modify: `pi/setup.sh`

- [ ] **Step 1: Rewrite setup.sh**

```bash
#!/usr/bin/env bash
# pi/setup.sh -- Heartwood Pi setup script (multi-instance)
# Run on a fresh Raspberry Pi OS Lite installation.
#
# Usage:
#   ./setup.sh                          # install system deps + code only
#   ./setup.sh --instance personal      # also create a named instance
#   ./setup.sh --instance personal --port 3000
set -euo pipefail

INSTANCE=""
PORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance) INSTANCE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "=== Heartwood Pi Setup ==="

# --- System user ---
sudo useradd -r -s /usr/sbin/nologin heartwood 2>/dev/null || true
sudo usermod -aG debian-tor heartwood 2>/dev/null || true
sudo mkdir -p /var/lib/heartwood /run/heartwood
sudo chown heartwood:heartwood /var/lib/heartwood /run/heartwood
sudo chmod 700 /var/lib/heartwood
sudo chmod 700 /run/heartwood

# --- Tor hostname copy drop-in ---
sudo mkdir -p /etc/systemd/system/tor@default.service.d
cat <<'DROPIN' | sudo tee /etc/systemd/system/tor@default.service.d/heartwood-hostname.conf >/dev/null
[Service]
ExecStartPost=/bin/sh -c 'for d in /var/lib/heartwood/*/; do cp /var/lib/tor/heartwood/hostname "$d/tor-hostname" 2>/dev/null && chown heartwood:heartwood "$d/tor-hostname"; done'
DROPIN

# --- Install heartwood binary ---
if [ -f "../target/release/heartwood-device" ]; then
    sudo cp ../target/release/heartwood-device /usr/local/bin/heartwood
    sudo chmod +x /usr/local/bin/heartwood
    echo "Installed heartwood binary"
else
    echo "Binary not found. Build with:"
    echo "  cargo build --release -p heartwood-device"
    echo "  cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device"
    exit 1
fi

# --- Install bunker sidecar ---
if [ -d "../bunker" ]; then
    sudo mkdir -p /opt/heartwood/bunker
    sudo cp ../bunker/index.mjs ../bunker/lib.mjs ../bunker/package.json /opt/heartwood/bunker/
    cd /opt/heartwood/bunker && sudo npm install --omit=dev 2>/dev/null && cd -
    sudo chown -R heartwood:heartwood /opt/heartwood
    echo "Installed bunker sidecar"
fi

# --- Install template units ---
sudo cp heartwood@.service /etc/systemd/system/
sudo cp heartwood-bunker@.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "Installed systemd template units"

# --- Create instance (optional) ---
if [ -n "$INSTANCE" ]; then
    echo "--- Creating instance: $INSTANCE ---"
    INST_DIR="/var/lib/heartwood/$INSTANCE"
    sudo mkdir -p "$INST_DIR"
    sudo chown heartwood:heartwood "$INST_DIR"
    sudo chmod 700 "$INST_DIR"

    if [ -n "$PORT" ]; then
        OVERRIDE_DIR="/etc/systemd/system/heartwood@${INSTANCE}.service.d"
        sudo mkdir -p "$OVERRIDE_DIR"
        cat <<EOF | sudo tee "$OVERRIDE_DIR/port.conf" >/dev/null
[Service]
Environment=HEARTWOOD_BIND=0.0.0.0:${PORT}
EOF
        echo "  Port: $PORT"
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable --now "heartwood@${INSTANCE}"
    sudo systemctl enable --now "heartwood-bunker@${INSTANCE}"
    echo "  Instance $INSTANCE started"
fi

echo ""
echo "=== Heartwood installed ==="
echo ""
echo "Create instances with:"
echo "  ./setup.sh --instance personal --port 3000"
echo "  ./setup.sh --instance forgesworn --port 3001"
echo ""
echo "Or manually:"
echo "  sudo mkdir -p /var/lib/heartwood/<name>"
echo "  sudo chown heartwood:heartwood /var/lib/heartwood/<name>"
echo "  sudo systemctl enable --now heartwood@<name> heartwood-bunker@<name>"
echo ""
echo "View logs:"
echo "  sudo journalctl -u 'heartwood@*' -u 'heartwood-bunker@*' -f"
```

- [ ] **Step 2: Verify script syntax**

Run: `bash -n pi/setup.sh`
Expected: Exit 0 (no syntax errors)

- [ ] **Step 3: Commit**

```bash
git add pi/setup.sh
git commit -m "feat: rewrite setup.sh for multi-instance deployment"
```

---

### Task 7: Remove old single-instance service files

**Files:**
- Delete: `pi/heartwood.service`
- Delete: `pi/heartwood-bunker.service`

- [ ] **Step 1: Remove old service files**

```bash
git rm pi/heartwood.service pi/heartwood-bunker.service
```

- [ ] **Step 2: Commit**

```bash
git commit -m "chore: remove single-instance service files (replaced by templates)"
```

---

### Task 8: Update CLAUDE.md and project docs

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the Build & Test table**

Add to the table in CLAUDE.md:

```markdown
| `cd bunker && npm test` | Bunker unit tests |
| `node tools/derive-client-key.mjs` | Derive NIP-46 client key from nsec-tree |
```

- [ ] **Step 2: Update the Structure section**

Add to the structure tree:

```
tools/
  derive-client-key.mjs   Standalone CLI for persistent NIP-46 client keys
  package.json             Tool dependencies (nsec-tree, nostr-tools)
```

Update the `pi/` section:

```
pi/
  setup.sh                    Pi deployment script (multi-instance)
  heartwood@.service          systemd template (Rust device)
  heartwood-bunker@.service   systemd template (Node.js bunker)
```

- [ ] **Step 3: Add multi-instance notes to Conventions or Common Pitfalls**

Add to Common Pitfalls:

```markdown
- The `HEARTWOOD_DATA_DIR` env var controls where each instance reads/writes data. If unset, falls back to `/var/lib/heartwood` for backwards compatibility.
- Systemd template units use `%i` for the instance name — `heartwood@personal.service` reads from `/var/lib/heartwood/personal/`
- Identity tree names use `/` as a namespace separator: `persona/forgesworn`, `client/bray`, `agent/dispatch`
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for multi-instance bunker and identity tree"
```

---

### Task 9: Full integration verification

**Files:** None (verification only)

- [ ] **Step 1: Run all Rust tests**

Run: `cargo test`
Expected: All tests PASS

- [ ] **Step 2: Run all bunker tests**

Run: `cd bunker && npm test`
Expected: All tests PASS (56 tests)

- [ ] **Step 3: Run clippy**

Run: `cargo clippy --all-targets`
Expected: No warnings

- [ ] **Step 4: Syntax check bunker**

Run: `node --check bunker/index.mjs`
Expected: Exit 0

- [ ] **Step 5: Verify derive-client-key runs**

Run: `node tools/derive-client-key.mjs`
Expected: Prints usage, exits 1

- [ ] **Step 6: Verify setup.sh syntax**

Run: `bash -n pi/setup.sh`
Expected: Exit 0
