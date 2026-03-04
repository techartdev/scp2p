# scp2p — Interactive CLI

`scp2p` is the reference command-line client for the SCP2P protocol. It is a fully **interactive shell**: no long lists of subcommands or flags to memorise — simply launch the binary and navigate through arrow-key menus.

---

## Installation

### One-line install (Linux / macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/techartdev/scp2p/main/install.sh | sh -s -- --tool cli
```

### One-line install (Windows PowerShell)

```powershell
$env:SCP2P_TOOL="cli"; irm https://raw.githubusercontent.com/techartdev/scp2p/main/install.ps1 | iex
```

### From crates.io

```bash
cargo install scp2p-cli
```

### From source

```bash
cargo install --path crates/scp2p-cli
```

---

## Quick start

```bash
# Start with defaults (database = scp2p.db, TCP = 7001, QUIC = 7000)
scp2p

# Explicit database, TCP/QUIC ports, and bootstrap peer
scp2p --db ~/mynode.db --port 7002 --quic-port 7001 --bootstrap 10.0.0.1:7001

# Multiple bootstrap peers
scp2p --bootstrap 10.0.0.1:7001,10.0.0.2:7001
```

---

## Startup flags

| Flag | Env variable | Default | Description |
|---|---|---|---|
| `--db <PATH>` | `SCP2P_DB` | `scp2p.db` | SQLite state database path |
| `--port <PORT>` | `SCP2P_PORT` | `7001` | TCP port for incoming peer connections |
| `--quic-port <PORT>` | `SCP2P_QUIC_PORT` | `--port - 1` | QUIC port (set `0` to disable QUIC) |
| `--bootstrap <IP:PORT>` | `SCP2P_BOOTSTRAP` | (empty) | Comma-separated bootstrap peer addresses |

All flags can also be supplied as environment variables — useful in scripts or containers.

---

## Interactive shell

On launch the node opens (or creates) the database, restores its identity, starts background TCP/QUIC listeners (if enabled), and presents the main menu:

```
  ╔══════════════════════════════════════════╗
  ║        SCP2P Interactive Shell           ║
  ╚══════════════════════════════════════════╝
  Node ID  : <hex>
  Share ID : <hex>
  Database : scp2p.db
  TCP port : 7001
  Network  : 1 bootstrap peer(s)

  What would you like to do?
> 📋  Status
  📤  Publish files
  📁  Publish folder
  📚  Browse / inspect a share
  🔔  Subscriptions
  🏘  Communities
  🔍  Search
  ⬇   Download by content ID
  ⬇   Download share
  🔄  Sync now
  🔑  Generate new keypair
  ❌  Quit
```

Navigate with **↑ ↓** arrow keys and **Enter**. Press **Escape** or **Ctrl+C** at any nested prompt to cancel and return to the main menu.

---

## Menu reference

### 📋 Status
Displays the current node ID, share ID, database path, listening port, subscription count, cached manifest count, and partial download count.

### 📤 Publish files
Prompts for:
- Share title
- File paths (comma-separated)
- Visibility (`private` / `public`)

Prints the share ID and manifest ID on success.

### 📁 Publish folder
Prompts for a directory path, a title, and visibility. Publishes all files under that directory as a single share.

### 📚 Browse / inspect a share
Presents a picker of all locally cached manifests for quick selection, or lets you enter a share ID manually. Lists every item in the share with its name, size, and content ID.

### 🔔 Subscriptions
Sub-menu with three options:

| Option | Description |
|---|---|
| List subscriptions | Print all active subscriptions with latest sequence number and manifest ID |
| Subscribe to a new share | Enter a share ID (hex) and optional public key |
| Sync subscriptions now | Trigger an immediate network sync (same as **Sync now**) |

### 🏘 Communities
Sub-menu for:
- Create a new community
- Join a community
- Leave a community
- Browse a community (participants and public shares)

### 🔍 Search
Prompts for a text query, runs it against the local subscription-scoped search index, and shows ranked results with score, share ID, content ID, and item name.

### ⬇ Download by content ID
Prompts for:
- Content ID (64 hex chars)
- Output file path
- Optional extra peer addresses

Downloads and cryptographically verifies the content from the peer swarm.

### ⬇ Download share
Prompts for a share ID and output directory. Lists all items and lets you select specific ones by number (or type `all`). Reports progress while transferring.

### 🔄 Sync now
Syncs all subscriptions over the DHT using configured bootstrap peers. If none are configured, prompts for peer addresses before syncing.

### 🔑 Generate new keypair
Generates a fresh Ed25519 keypair and prints:
- Private key (hex) — **store it securely**
- Public key (hex)
- Node ID
- Share ID

---

## Tips

- **Offline use:** search and browsing work without any network connection as long as you have locally synced manifests.
- **Persistent identity:** the node key is stored in the database; the same Node ID and Share ID appear on every launch against the same `--db`.
- **Scripting:** set `SCP2P_DB`, `SCP2P_PORT`, `SCP2P_QUIC_PORT`, and `SCP2P_BOOTSTRAP` environment variables to avoid repeating flags in scripts.
- **Multiple nodes:** point different instances at different `--db` paths to run multiple independent identities on the same machine.
