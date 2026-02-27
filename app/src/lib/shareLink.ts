// ── Share link encoding/decoding ────────────────────────────────────────
// Format: scp2p://s/<base64url(share_id_32bytes || share_pubkey_32bytes)>
// Total raw payload: 64 bytes → 86 chars base64url → ~96 char URI.

const SHARE_LINK_PREFIX = "scp2p://s/";

/** Encode share_id + share_pubkey (both hex) into a compact share link. */
export function encodeShareLink(
  shareIdHex: string,
  sharePubkeyHex: string
): string {
  const raw = hexToBytes(shareIdHex + sharePubkeyHex); // 64 bytes
  return SHARE_LINK_PREFIX + bytesToBase64url(raw);
}

/** Decode a share link back to { shareIdHex, sharePubkeyHex }.
 *  Throws if the link is malformed. */
export function decodeShareLink(link: string): {
  shareIdHex: string;
  sharePubkeyHex: string;
} {
  const trimmed = link.trim();
  if (!trimmed.startsWith(SHARE_LINK_PREFIX)) {
    throw new Error("Not a valid scp2p share link");
  }
  const b64 = trimmed.slice(SHARE_LINK_PREFIX.length);
  const raw = base64urlToBytes(b64);
  if (raw.length !== 64) {
    throw new Error(
      `Invalid share link payload: expected 64 bytes, got ${raw.length}`
    );
  }
  return {
    shareIdHex: bytesToHex(raw.slice(0, 32)),
    sharePubkeyHex: bytesToHex(raw.slice(32, 64)),
  };
}

/** Returns true if the string looks like a scp2p share link. */
export function isShareLink(text: string): boolean {
  return text.trim().startsWith(SHARE_LINK_PREFIX);
}

// ── Base64url helpers (no padding, URL-safe) ────────────────────────────

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBytes(b64: string): Uint8Array {
  // Restore standard base64
  let s = b64.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ── Hex helpers ─────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, "");
  if (clean.length % 2 !== 0) throw new Error("Odd-length hex string");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
