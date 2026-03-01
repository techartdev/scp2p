# SCP2P: Subscribed Catalog P2P

Welcome to **SCP2P** (Subscribed Catalog P2P) — a decentralized, cryptographically-secure communication and data sharing protocol designed for the modern web.

SCP2P is built on a simple yet powerful idea: **you should own your data and your discovery.** Unlike traditional platforms that rely on central servers or global uncurated search, SCP2P empowers individuals and communities to build their own private or public networks of trust.

---

## 🚀 What is SCP2P?

SCP2P is a peer-to-peer (P2P) software suite and protocol that allows users to publish, discover, and share "Catalogs" (Manifests) of content without a middleman. 

At its core, SCP2P is:
- **Subscription-Centric:** You only see and search what you choose to follow. No global noise, just curated signal.
- **Fully Decentralized:** No central servers, no "cloud" ownership. Data moves directly between peers.
- **Cryptographically Secure:** Every share is signed by its publisher, and every byte of data is verified for integrity using modern primitives (Ed25519, BLAKE3).
- **NAT-Friendly:** Designed to work across home routers and mobile networks using QUIC and intelligent relaying.
- **Zero Configuration:** Features built-in LAN discovery (mDNS) so you can start sharing with devices on your local network instantly.
- **Offline-First:** Search and discovery work even without an internet connection, as long as you have local peers.

---

## 💎 Why SCP2P? (Benefits vs. Existing Software)

| Feature | Centralized (Social/Cloud) | Traditional P2P (BitTorrent) | **SCP2P** |
| :--- | :--- | :--- | :--- |
| **Privacy** | Low (Data mined/monitored) | Medium (Public IP exposure) | **High** (Encrypted, scoped search) |
| **Censorship** | Easy (Central kill-switch) | Hard | **Impossible** (No central authority) |
| **Search** | Algorithmic/Ad-driven | Global/Uncurated | **Subscribed/Curated** |
| **Integrity** | Trusted Service | Variable | **Cryptographically Guaranteed** |
| **Ownership** | Platform-owned | Shared Swarm | **Self-Signed Sovereignty** |
| **Community** | Platform-locked | Fragmented | **Built-in Communities** |

---

## ⚙️ How It Works (Simplified)

SCP2P simplifies complex P2P technology into a straightforward lifecycle:

1.  **Create a Share:** You bundle files or text into a "Share" on your device. This creates a cryptographically signed **Manifest** (a catalog). You control the visibility: make it **Public** for anyone to find, or **Private** so only those with the ID can subscribe.
2.  **Publish to the DHT:** Your node announces a small "pointer" to the Decentralized Hash Table (DHT). This distributed ledger tells the network that a new version of your share exists without revealing its content.
3.  **Onboarding & Discovery:** Others join your circle via a simple **Invite Link** or find you via **LAN Discovery** and **Communities**. If you are behind a firewall, **Relays** (standard nodes with extra capacity) help bridge the connection without ever seeing your unencrypted data.
4.  **Local Search:** Once subscribed, your peers' catalogs are indexed locally on *your* device. When you search, you are searching your own curated world—not a global, spam-filled index.
5.  **Swarm Download:** When someone wants a file, they download "chunks" from you and any other peers who already have it. This makes the network faster as more people join (Swarming).

---

SCP2P is designed for everyone who values digital sovereignty:
- **Normal People:** Share photos with family, sync documents across devices, or participate in private hobbyist circles.
- **Developers:** Use it as a decentralized backend for data distribution, a P2P package manager, or a secure communication layer for apps.
- **Groups & Communities:** Build independent digital spaces for neighborhoods, activists, or specialized interest groups without fear of platform de-platforming.

---

## 💡 Use Cases

### 🏠 For Normal People
- **Private Family Cloud:** Share high-res photos and home videos with family members without uploading them to a big-tech cloud.
- **Secure File Sync:** Keep your important documents synced between your laptop at home and your computer at work, peer-to-peer.
- **Creative Collaboration:** Musicians, artists, and writers can share large project files and assets directly with collaborators without hitting storage limits.
- **Digital Archive:** Create a personal "Share" of your favorite recipes or books and subscribe to your friends' collections.

### 🛠️ For Developers
- **P2P Package Distribution:** Distribute library binaries or assets directly to users, reducing server costs and increasing speed via local swarming. Perfect for game assets or large SDKs.
- **Mirroring & Caching:** Speed up your entire team by acting as a local peer-to-peer cache for common dependencies, reducing external bandwidth.
- **Decentralized Documentation:** Host and sync project documentation across contributor nodes, ensuring it's always available even offline.
- **Edge Computing Data Bus:** Use the DHT and manifest system to coordinate state between distributed edge nodes or IoT devices.
- **CI/CD Artifact Sharing:** Speed up build pipelines by sharing artifacts between build nodes on the same network without hitting external storage.

### 🌐 For Groups & Communities
- **Local Neighborhood Networks:** Share local news, tool-lending catalogs, or event info within a physical community. Works even if the local ISP goes down.
- **Research Collectives:** Securely share datasets and papers within a closed group of researchers with verifiable version history.
- **Resilient Communication:** Maintain a shared "catalog" of critical information that remains accessible even if the main internet backbone is restricted.

---

## �️ Privacy & Security by Design

SCP2P isn't just secure; it's architected to protect your digital footprint:

-   **Zero Tracking:** Since there are no central servers, there is no one to track your searches, downloads, or social graphs.
-   **End-to-End Integrity:** Every piece of data is hashed and signed. You don't just "trust" the sender; you verify the math.
-   **Metadata Privacy:** Search is performed locally on *your* hardware. Your interests never leave your device.
-   **No Global Index:** By eliminating global search, we eliminate global spam and mass-surveillance crawlers.

---

We are currently in **v0.1 Prototype** phase. We are building the foundations of a global communication standard.

### ✅ What's Working (Existing)
- **Core Protocol:** Ed25519 identities, BLAKE3 content addressing, and CBOR-framed messaging.
- **Networking:** Multi-transport support (QUIC and TCP) with authenticated handshakes.
- **DHT (Kademlia-lite):** Decentralized peer discovery and content location hints.
- **Content Sharing:** Multi-file and folder sharing with verified swarm downloading.
- **Desktop App:** A functional Windows/macOS/Linux client built with Tauri and React.
- **Persistence:** Durable local state using SQLite.

### 🏗️ What's Coming (Planned)
- **Mobile Support:** Native Android and iOS clients for true portability.
- **Universal Packaging:** We target support for every mainstream package manager (npm, cargo, brew, apt, chocolatey, etc.).
- **Enhanced NAT Traversal:** More robust relaying and hole-punching for the toughest network environments.
- **SDKs:** Stable libraries for multiple languages to allow any dev to build on SCP2P.
- **Global Reach:** Intelligent community discovery and advanced trust-tier systems.

---

## 🌍 Global Vision & Portability

SCP2P isn't just a tool; it's a **global standard in the making.** Our mission is to provide the same seamless, secure experience across every environment:

-   **Any Device:** From high-end desktop workstations and always-on servers to smartphones and low-power IoT devices.
-   **Any OS:** First-class support for Windows, macOS, Linux, Android, and iOS.
-   **Any Platform:** We are committed to bringing SCP2P to every mainstream package manager. Whether you use `npm`, `cargo`, `brew`, `apt`, `pkg`, or `chocolatey`, SCP2P will be a single command away.

We believe that decentralized communication should be as easy to install and use as any mainstream app, without sacrificing the privacy of the individual.

---

## 🛠️ Getting Started (For Developers)

The project is structured as a Rust workspace:

- `crates/scp2p-core`: The heart of the protocol.
- `crates/scp2p-cli`: A reference command-line interface.
- `app/`: The Tauri + React desktop application.

### Quick Start (CLI)
```bash
# Clone and test
cargo test

# Generate a node identity
cargo run -p scp2p-cli -- gen-identity

# Start a node
cargo run -p scp2p-cli -- start
```

---

## 🤝 Join the Movement

SCP2P is open source and community-driven. We welcome contributors, testers, and visionaries.

- **Found an issue?** Open a GitHub Issue.
- **Want to contribute?** Check out `AGENTS.md` and `PLAN.md` for current priorities.
- **Stay tuned:** We are working on providing native packages for all major OS platforms soon!

---

*“Own your catalog, subscribe to your world.”*
