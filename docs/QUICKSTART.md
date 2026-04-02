# Run Your Own Heartwood

A step-by-step guide to running Heartwood on a Raspberry Pi. No programming experience needed.

## What you need

- A **Raspberry Pi** (any model with WiFi — Pi 3, Pi 4, Pi Zero 2 W, Pi 5)
- A **micro SD card** (8 GB or larger)
- A **power supply** for your Pi
- A **computer** on the same WiFi network (to access the web UI)
- Your **Nostr nsec** (the private key you want Heartwood to protect)

## Step 1: Flash the SD card

1. Download [Raspberry Pi Imager](https://www.raspberrypi.com/software/) on your computer
2. Insert the SD card into your computer
3. Open Raspberry Pi Imager:
   - **Operating System:** Raspberry Pi OS Lite (64-bit)
   - **Storage:** your SD card
   - Click the **gear icon** (or "Edit Settings") before writing:
     - Set a **hostname** (e.g. `heartwood`)
     - Enable **SSH** (use password authentication)
     - Set a **username** (e.g. `satoshi`) and **password**
     - Configure your **WiFi** network name and password
   - Click **Write** and wait for it to finish

4. Eject the SD card, put it in the Pi, and plug in power
5. Wait 2–3 minutes for the Pi to boot and connect to WiFi

## Step 2: Connect to the Pi

On your computer, open a terminal (Terminal on Mac, PowerShell on Windows):

```bash
ssh satoshi@heartwood.local
```

Replace `satoshi` with the username you chose. Type `yes` when asked about the fingerprint, then enter your password.

If `heartwood.local` doesn't work, check your router's admin page for the Pi's IP address and use that instead:

```bash
ssh satoshi@192.168.1.XXX
```

## Step 3: Install Heartwood

Run this one command on the Pi:

```bash
curl -sL https://github.com/forgesworn/heartwood/releases/latest/download/install.sh | sudo bash
```

This downloads the latest release binary, installs Node.js and the NIP-46 bunker sidecar, configures Tor, creates system services, and starts everything. It takes about 2–3 minutes.

When it finishes, you'll see your `.onion` address — save it somewhere. You can also find it later:

```bash
sudo cat /var/lib/tor/heartwood/hostname
```

## Step 4: Open the web UI

On your computer, open a web browser and go to:

```
http://heartwood.local:3000
```

(or `http://192.168.1.XXX:3000` if you used an IP address)

You should see the Heartwood setup screen.

## Step 5: Set up your key

1. Select **Bunker** mode (recommended — keeps your existing npub)
2. Paste your **nsec** into the text box
3. Choose a **4–8 digit PIN** — this encrypts your key on the SD card
4. Confirm the PIN
5. Click **Initialise**

Your npub will appear on screen. The nsec is now encrypted on the Pi with AES-256-GCM — you won't need to paste it again.

The bunker sidecar connects to relays automatically. Within a few seconds, the **Relays** section will show green dots next to each connected relay.

## Step 6: Connect from a Nostr client

1. In the Heartwood web UI, find the **Bunker connection string** (starts with `bunker://...`)
2. Click **Copy**
3. Open your Nostr client (Bark, NostrHub, Amethyst, etc.)
4. Look for "Login with bunker" or "NIP-46 / Nostr Connect"
5. Paste the bunker connection string

The client will appear in the **Bunker Clients** section of the web UI as "Awaiting approval". Give it a label (e.g. "Bark" or "My phone") and click **Approve**.

Once approved, the client can request signatures. Your nsec never leaves the device.

## Step 7: Set a device password (recommended)

In the web UI, scroll down to **Device Password** and set one. This protects the web UI with HTTP Basic Auth — anyone on your network would need the password to access settings.

## Step 8: Access from anywhere (Tor)

If Tor is enabled (check the toggle in the web UI), you can access Heartwood from anywhere using your `.onion` address. The address is shown in the web UI with a copy button.

This works from any network — VPN, coffee shop WiFi, your phone on mobile data. You need [Tor Browser](https://www.torproject.org/download/) or a Tor-capable client.

## Daily use

- **When the Pi boots**, Heartwood starts automatically but is **locked**. Open the web UI and enter your PIN to unlock.
- **When you're done**, click **Lock device** in the web UI. The decrypted key is cleared from memory.
- **If you lose power**, the Pi boots locked. Your key is safe — it's encrypted on the SD card.
- **If you forget your PIN**, you'll need to reset the device and set up again with your nsec.

## The web UI at a glance

- **Status bar** — device status and version
- **Bunker connection string** — copy this into your Nostr client
- **Relays** — green/red/grey dots show which relays the bunker is connected to (updates every 15 seconds)
- **Bunker Clients** — see pending and approved NIP-46 clients, label them, approve or revoke
- **Tor** — enable/disable the hidden service
- **Device Password** — protect the web UI

## Troubleshooting

**Can't find the Pi on the network?**
- Wait 2–3 minutes after plugging in — it takes time to boot and connect to WiFi
- Try pinging it: `ping heartwood.local`
- Check your router's admin page for connected devices
- If you're on a VPN, disconnect first — VPNs hide local network devices

**Web UI shows "Connection failed"?**
- Make sure you're on the same WiFi as the Pi
- Try the IP address directly: `http://192.168.1.XXX:3000`

**Client stuck on "Verifying identity..."?**
- Make sure the Pi is unlocked (enter your PIN in the web UI first)
- Check the relay dots — at least one should be green
- Check the bunker is running: `ssh satoshi@heartwood.local "sudo systemctl status heartwood-bunker"`
- Restart the bunker: `ssh satoshi@heartwood.local "sudo systemctl restart heartwood-bunker"`

**Tor not working / .onion address missing?**
- Check if Tor is running: `ssh satoshi@heartwood.local "sudo systemctl status tor@default"`
- If Tor failed with "Permissions on directory too permissive", fix it:
  ```bash
  ssh satoshi@heartwood.local "sudo chmod 0700 /var/lib/tor/heartwood/ && sudo systemctl restart tor@default"
  ```
- After Tor restarts, restart the bunker too: `ssh satoshi@heartwood.local "sudo systemctl restart heartwood-bunker"`

**Forgot your PIN?**
- SSH into the Pi and delete the encrypted secret, then set up again:
  ```bash
  ssh satoshi@heartwood.local "sudo rm /var/lib/heartwood/master.secret"
  ```
  Then refresh the web UI — you'll see the setup screen.

## Updating

When a new version is released, SSH into the Pi and re-run the installer:

```bash
curl -sL https://github.com/forgesworn/heartwood/releases/latest/download/install.sh | sudo bash
```

This downloads the latest binary and bunker code, restarts the services, and preserves your existing configuration.

## Developer quickstart

If you want to build from source instead of using the installer:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Clone and build
git clone https://github.com/forgesworn/heartwood.git
cd heartwood
cargo build --release -p heartwood-device

# Install bunker dependencies
cd bunker && npm install && cd ..

# Run the setup script
cd pi && sudo bash setup.sh
```

Cross-compile for Pi from another machine:

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu -p heartwood-device
```

## Security notes

- **AES-256-GCM encryption at rest** — your nsec is encrypted with a key derived from your PIN via Argon2id. The PIN is never stored.
- **The nsec never leaves the device** — only signatures and public keys are sent over relays.
- **Systemd hardening** — both services run with `ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`, and restricted capabilities.
- **Tor by default** — no port forwarding, no clearnet exposure, no IP address leaked.
- **Per-client kind restrictions** — control what each paired app can sign.
- **Device password** — protects the web UI with Argon2id-hashed HTTP Basic Auth.
