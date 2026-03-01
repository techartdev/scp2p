# Security Policy

## Security Philosophy

SCP2P is a decentralized, peer-to-peer protocol designed for sovereign data exchange. While we strive to implement robust cryptographic protections and follow security best practices, users must understand the nature of decentralized software.

## Legal Disclaimer & Limitation of Liability

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.**

1.  **No Liability:** In no event shall the authors, maintainers, or contributors be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
2.  **User Responsibility:** The developers of SCP2P provide the tools, but have no control over how they are used. Users are solely responsible for their own actions and the content they share or subscribe to.
3.  **Illegal Activities:** We do not condone, encourage, or support the use of SCP2P for any illegal activities. Users must comply with all applicable local, national, and international laws. The developers are not in charge of, nor responsible for, any misuse of this software by third parties.
4.  **No Central Authority:** Because SCP2P is fully decentralized, there is no central authority that can block, moderate, or remove content. Users must exercise their own judgment and use the built-in trust and subscription models to curate their own experience.

## Reporting a Vulnerability

We take the security of SCP2P seriously. If you believe you have found a security vulnerability, please report it to us responsibly.

**Please do not report security vulnerabilities via public GitHub issues.**

Instead, please send a detailed report to the project maintainers. We will acknowledge your report and provide a timeline for a fix if necessary.

## Supported Versions

Currently, only the latest version in the `main` branch is supported for security updates as we are in the **v0.1 Prototype** phase.

## Security Features in SCP2P

-   **Cryptographic Identity:** Every node and share is tied to an Ed25519 keypair.
-   **Content Integrity:** All data is verified using BLAKE3 hashes.
-   **Authenticated Transport:** All peer-to-peer connections use QUIC or TLS with mandatory identity binding.
-   **Local Indexing:** Search metadata never leaves your device, preventing central profiling.
