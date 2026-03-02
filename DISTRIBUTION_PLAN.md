# SCP2P Distribution and Interoperability Plan

This document outlines the strategy for bringing SCP2P to all major operating systems and programming languages, ensuring broad adoption and ease of deployment for relays and client libraries.

## 1. Multi-Platform Support Strategy

SCP2P is built in Rust, providing a solid foundation for cross-platform support.

### 1.1 Desktop Application (Tauri)
- **Status**: Currently implemented in `app/` using Tauri v2 (Rust) + React (TypeScript).
- **Target**: provide a user-friendly GUI for non-technical users on all major desktop platforms.
- **Distribution**:
    - **Windows**: `.msi` (Wix), `.exe` (NSIS), Winget.
    - **macOS**: `.dmg`, `.app`, Homebrew Cask.
    - **Linux**: `.deb` (Debian/Ubuntu), `.rpm` (Fedora/RHEL), `.AppImage`.
- **Update Mechanism**: Use Tauri's built-in updater for seamless background updates.

### 1.2 Desktop CLI (scp2p-cli)
- **Status**: Supported via `crates/scp2p-cli`.
- **Target**: Power users, automated scripts, and headless environments.
- **Distribution**:
    - **Windows**: Winget, Scoop.
    - **macOS**: Homebrew (Formula).
    - **Linux**: AUR (Arch), custom PPA (Ubuntu).

### 1.3 Mobile OS (Android, iOS)
- **Strategy**: Use `UniFFI` to generate high-level bindings.
- **Android**: Kotlin/Java bindings distributed via Maven Central.
- **iOS**: Swift bindings distributed via Swift Package Manager (SPM) and CocoaPods.

## 2. Language Wrappers & Libraries

To enable developers to use SCP2P in their preferred stack, we will provide idiomatic wrappers.

| Language | Technology | Package Manager | Status |
| :--- | :--- | :--- | :--- |
| **Rust** | Native | crates.io | In Progress |
| **TypeScript/JS** | `napi-rs` (Node) / `wasm-bindgen` (Web) | npm | Planned |
| **Python** | `uniffi-rs` / `PyO3` | PyPI | Planned |
| **Kotlin (Android)** | `uniffi-rs` | Maven Central | Planned |
| **Swift (iOS/macOS)** | `uniffi-rs` | SPM | Planned |
| **C# (.NET)** | `uniffi-rs` | NuGet | Planned |
| **Go** | `cgo` / C-FFI | Go Modules | Planned |
| **C/C++** | `cbindgen` | System PMs | Planned |

### 2.1 Development Requirements for Wrappers
- **Async Bridging**: Rust's `Tokio` runtime must be managed within the wrapper. For UniFFI, this involves using `uniffi::export` and potentially a global runtime or per-object executor.
- **Memory Management**: Ensure proper disposal of `NodeHandle` across the FFI boundary to prevent memory leaks in managed languages (Java/Python/JS).
- **Serialization**: Use CBOR for internal state transfer where possible, or flatten structures into FFI-compatible types.

### 2.2 Package Manager Publishing Instructions

#### Rust (crates.io)
1. Clean up `Cargo.toml` metadata (description, repository, keywords).
2. Run `cargo publish -p scp2p-core`.

#### JavaScript/TypeScript (npm)
1. Use `napi-rs` to generate Node.js addons.
2. Target `index.d.ts` generation for TypeScript support.
3. Publish via `npm publish --access public`.

#### Python (PyPI)
1. Use `maturin` to build and publish.
2. Configure `pyproject.toml` to use `maturin` as the build backend.
3. Run `maturin publish`.

#### Android (Maven Central)
1. Generate AAR using UniFFI's Kotlin scaffolding.
2. Use `nexus-staging-maven-plugin` or similar for OSSRH publishing.

#### iOS (Swift Package Manager)
1. Generate XCFramework using UniFFI.
2. Host the binary on GitHub Releases and provide a `Package.swift` pointing to it.

#### C# / .NET (NuGet)
1. Use UniFFI's C# scaffolding.
2. Build a `.nupkg` containing the native DLL/so/dylib and the generated C# bindings.
3. Publish to `nuget.org`.

## 3. Minimal Relay (scp2p-relay)

A lightweight, headless relay implementation designed for servers.

### 3.1 Features
- Stripped-down core: No search index, no content storage (unless caching is enabled).
- Focus on `RelayManager` and `RelayTunnelRegistry`.
- Low memory/CPU footprint.
- Configuration via environment variables or minimal YAML.

### 3.2 Distribution
- **Docker**: Official image on Docker Hub (`scp2p/relay`).
- **Binary**: Static binaries for Linux (x86_64, ARM64) built via `musl`.
- **Package Managers**: 
    - **Homebrew**: `brew install techartdev/tap/scp2p-relay`
    - **APT**: Provide a `.deb` via a PPA or custom repository.
    - **Winget**: Submit a manifest to the `microsoft/winget-pkgs` repository.

## 4. Implementation Roadmap

### Phase 1: Core Refinement (Current)
- Finalize `scp2p-core` API stability.
- Ensure all public types are `FFI-safe` or have conversion paths.

### Phase 2: Desktop & Relay Apps
- **Desktop**: Finalize Tauri v2 build pipeline for all three OSs.
- **Relay**: Extract `scp2p-relay` from `scp2p-core`.
- **Distribution**: Set up CI/CD for multi-arch binary releases and signed installers.

### Phase 3: Language Bindings (The "Big Three")
- **Node.js**: Priority 1 for web integrations and desktop apps (Electron/Capacitor).
- **Python**: Priority 2 for research and scripting.
- **Mobile (Kotlin/Swift)**: Priority 3 for mobile client development.

### Phase 4: Package Manager Integration
- Automate publishing to `npm`, `PyPI`, `crates.io`.
- Submit to Homebrew, Winget, and Linux distros.

### 5.1 `crates/scp2p-ffi` (New)
A dedicated crate for exposing the Rust core to other languages.
- **Technology**: `uniffi` for high-level languages (Swift, Kotlin, Python) and `cbindgen` for C/C++.
- **Scope**: Wrap `NodeHandle` and its associated types (`ShareId`, `ContentId`, `SearchResult`) into FFI-compatible structures.
- **Async Strategy**: Implement a bridge between Rust's `Tokio` and the target language's async/await (e.g., via `uniffi::export` which handles `async fn`).

### 5.2 `crates/scp2p-relay` (New)
A minimal executable crate for infrastructure providers.
- **Dependencies**: Depends on `scp2p-core` but disables optional features like `search` and `local-storage` where possible to minimize footprint.
- **CLI Interface**: Uses `clap` for configuration (ports, bootstrap peers, bandwidth limits).
- **Service Support**: Include `systemd` unit files and Docker Compose templates for easy deployment.

### 5.3 CI/CD & Package Manager Automation
- **GitHub Actions**:
    - Build binaries for `x86_64` and `aarch64` (ARM) across Windows, Linux (musl), and macOS.
    - Automate `cargo publish`, `npm publish`, and `maturin publish`.
    - Generate and upload `.deb`, `.rpm`, `.msi`, and `.dmg` artifacts to GitHub Releases.
- **Release Channel**: Maintain `stable` and `nightly` channels for library consumers.
