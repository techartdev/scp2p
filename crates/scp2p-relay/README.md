# scp2p-relay

Standalone relay node for the [SCP2P](https://github.com/) peer-to-peer network.

Relays bridge peers that cannot reach each other directly (NAT, firewalls).
The more relays the network has, the more resilient and accessible it becomes.
**If you have a server with a public IP, running a relay is the single most
impactful contribution you can make to the community.**

---

## What it does

- Accepts tunnel registrations from peers behind NAT.
- Forwards encrypted data between registered peers (the relay sees only
  ciphertext — it cannot read the content).
- Participates in the DHT so clients discover it automatically.
- Persists its node identity across restarts so clients can pin it.

## What it does NOT do

- It does not store or serve content (no disk-space cost beyond the state DB).
- It does not subscribe to or index any shares.
- It does not require any special hardware or operating system.

---

## Installation

### One line — Linux / macOS

```sh
curl -sSfL https://raw.githubusercontent.com/techartdev/scp2p/main/install.sh | sh
```

Installs to `/usr/local/bin` (with `sudo`) or `~/.local/bin` (without).
Pass `--version 0.1.0` to pin a specific release, or `--dir ~/bin` to change
the destination:

```sh
curl -sSfL https://raw.githubusercontent.com/techartdev/scp2p/main/install.sh | sh -s -- --version 0.1.0
```

### One line — Windows (PowerShell / Windows Terminal)

```powershell
irm https://raw.githubusercontent.com/techartdev/scp2p/main/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\scp2p-relay\` and adds it to your user PATH.
Pin a version with `$env:SCP2P_VERSION="0.1.0"` before running, or set
`$env:SCP2P_INSTALL_DIR` to change the destination.

### Via cargo

```sh
cargo install scp2p-relay
```

### From source

```sh
git clone https://github.com/techartdev/scp2p
cd scp2p
cargo install --path crates/scp2p-relay
```

### Pre-built binaries

Download directly from the [releases page](https://github.com/techartdev/scp2p/releases):

| File | Platform |
|---|---|
| `scp2p-relay-linux-x86_64` | Linux x86-64 |
| `scp2p-relay-linux-aarch64` | Linux arm64 (Raspberry Pi, Graviton) |
| `scp2p-relay-macos-x86_64` | macOS Intel |
| `scp2p-relay-macos-aarch64` | macOS Apple Silicon (M1/M2/M3) |
| `scp2p-relay-windows-x86_64.exe` | Windows 10/11 |

---

## Quick start

```sh
# Minimal — listens on default ports (TCP 7001, UDP 7000).
# Fine for a server where the bind address IS the public address.
scp2p-relay

# With bootstrap peers so the relay joins an existing network:
scp2p-relay --bootstrap seed1.example.com:7001 --bootstrap seed2.example.com:7001

# Behind DNAT (bind address differs from the public address):
scp2p-relay \
    --bind-tcp  0.0.0.0:7001 \
    --bind-quic 0.0.0.0:7000 \
    --bootstrap seed1.example.com:7001 \
    --announce  tcp://203.0.113.1:7001 \
    --announce  quic://203.0.113.1:7000

# Using a config file:
scp2p-relay --config /etc/scp2p-relay/relay.toml
```

---

## Configuration

Settings are applied in this priority order (highest wins):

1. **CLI flags**
2. **TOML config file** (`--config` / `SCP2P_CONFIG`)
3. **Compiled defaults**

### TOML config file

```toml
# /etc/scp2p-relay/relay.toml

# Where to store the state database (node identity, peer records).
data_dir = "/var/lib/scp2p-relay"

# Listener addresses.  Set to "" to disable a transport.
bind_tcp  = "0.0.0.0:7001"
bind_quic = "0.0.0.0:7000"

# Bootstrap peers to join the network.
bootstrap_peers = [
    "tcp://seed1.example.com:7001",
    "tcp://seed2.example.com:7001",
]

# Public addresses announced to DHT clients.
# Only needed when the bind address != external address (DNAT).
announce_addrs = [
    "tcp://203.0.113.1:7001",
    "quic://203.0.113.1:7000",
]

# Relay capacity hints (informational, not enforced by the network).
max_tunnels     = 64          # default: 64
bandwidth_class = "medium"    # "low" | "medium" | "high"

# How often to re-publish the relay announcement to the DHT (seconds).
announce_interval_secs = 1800  # default: 1800 (30 min)

# Logging.
log_level  = "info"   # trace | debug | info | warn | error
log_format = "text"   # text | json
```

### Environment variables

Every flag has a corresponding `SCP2P_*` environment variable:

| Variable | Equivalent flag |
|---|---|
| `SCP2P_CONFIG` | `--config` |
| `SCP2P_DATA_DIR` | `--data-dir` |
| `SCP2P_BIND_TCP` | `--bind-tcp` |
| `SCP2P_BIND_QUIC` | `--bind-quic` |
| `SCP2P_BOOTSTRAP` | `--bootstrap` (comma-separated) |
| `SCP2P_ANNOUNCE_ADDRS` | `--announce` (comma-separated) |
| `SCP2P_MAX_TUNNELS` | `--max-tunnels` |
| `SCP2P_BANDWIDTH_CLASS` | `--bandwidth-class` |
| `SCP2P_ANNOUNCE_INTERVAL_SECS` | `--announce-interval-secs` |
| `SCP2P_LOG_LEVEL` | `--log-level` |
| `SCP2P_LOG_FORMAT` | `--log-format` |

---

## Firewall / port forwarding

Open **both** ports on your firewall / NAT router:

| Port | Protocol | Purpose |
|------|----------|---------|
| 7001 | TCP | TLS-over-TCP listener |
| 7000 | UDP | QUIC/UDP listener |

You can use non-standard ports with `--bind-tcp` / `--bind-quic`.

---

## Running as a system service

### systemd (Linux)

```ini
# /etc/systemd/system/scp2p-relay.service
[Unit]
Description=SCP2P Relay Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=scp2p
ExecStart=/usr/local/bin/scp2p-relay --config /etc/scp2p-relay/relay.toml
Restart=on-failure
RestartSec=5s
# Structured JSON logs integrate with journald
Environment=SCP2P_LOG_FORMAT=json

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now scp2p-relay
journalctl -u scp2p-relay -f
```

### Docker

```dockerfile
FROM debian:bookworm-slim
COPY scp2p-relay /usr/local/bin/scp2p-relay
RUN chmod +x /usr/local/bin/scp2p-relay
EXPOSE 7000/udp 7001/tcp
ENV SCP2P_LOG_FORMAT=json
ENTRYPOINT ["scp2p-relay"]
```

```sh
docker run -d \
  -p 7000:7000/udp \
  -p 7001:7001/tcp \
  -v /var/lib/scp2p-relay:/root/.local/share/scp2p-relay \
  -e SCP2P_BOOTSTRAP=seed1.example.com:7001 \
  scp2p-relay
```

### Windows service (via NSSM)

```bat
nssm install scp2p-relay "C:\Program Files\scp2p-relay\scp2p-relay.exe"
nssm set scp2p-relay AppParameters --config "C:\ProgramData\scp2p-relay\relay.toml"
nssm start scp2p-relay
```

---

## Default data directories

| OS | Default path |
|----|-------------|
| Linux | `~/.local/share/scp2p-relay/` |
| macOS | `~/Library/Application Support/scp2p-relay/` |
| Windows | `%APPDATA%\scp2p-relay\` |

Override with `--data-dir` or `SCP2P_DATA_DIR`.

---

## Node identity

On first start, `scp2p-relay` generates a stable Ed25519 identity and stores it
in the state database (`relay.db`).  The public key is printed at startup:

```
INFO relay node ready  pubkey=aabb...  version=0.1.0
```

Keep the `relay.db` file safe — it contains the private key.  If you lose it,
the relay gets a new identity and clients that have pinned the old key will stop
trusting it.

---

## License

Mozilla Public License 2.0 — see [LICENSE](../../LICENSE).
