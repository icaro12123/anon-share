import { expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { BIP39_ITALIAN } from './bip39-it.ts';

export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.trim().toLowerCase();
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.substring(i, i + 2), 16);
    if (isNaN(byte)) {
      throw new Error(`Invalid hex byte at index ${i}`);
    }
    bytes[i / 2] = byte;
  }
  return bytes;
}

/**
 * Generates a cryptographically secure 256-bit (32 bytes) room secret S_room.
 */
export function generateRoomSecret(): Uint8Array {
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  return secret;
}

/**
 * Derives Noise PSK and Nostr RoomTag from S_room per Section 3.1.
 */
export function deriveDirectKeys(roomSecret: Uint8Array): {
  noisePsk: Uint8Array;
  roomTag: string;
} {
  if (roomSecret.length !== 32) {
    throw new Error('Room secret must be exactly 32 bytes');
  }

  // PSK_Noise = HKDF-Expand(S_room, "ANONSHARE-v1-NOISE-PSK", 32)
  const noisePsk = expand(sha256, roomSecret, 'ANONSHARE-v1-NOISE-PSK', 32);

  // RoomTag = HKDF-Expand(S_room, "ANONSHARE-v1-NOSTR-ROOM-TAG", 32) (encoded as 64-char hex)
  const roomTagBytes = expand(sha256, roomSecret, 'ANONSHARE-v1-NOSTR-ROOM-TAG', 32);
  const roomTag = toHex(roomTagBytes);

  return { noisePsk, roomTag };
}

/**
 * Derives Client Authorization key for Tor mode per Section 4.
 */
export function deriveTorAuthKey(roomSecret: Uint8Array): Uint8Array {
  if (roomSecret.length !== 32) {
    throw new Error('Room secret must be exactly 32 bytes');
  }
  return expand(sha256, roomSecret, 'ANONSHARE-v1-HS-CLIENT-AUTH', 32);
}

/**
 * Derives 6 SAS verification words (66 bits) from final handshake hash h per Section 3.3.
 * SAS_Bytes = HKDF-Expand(h, "ANONSHARE-v1-SAS-VERIFICATION", 9)
 * 66 bits are partitioned into 6 indices of 11 bits (0..2047) mapped to BIP-39 Italian wordlist.
 */
export function deriveSasWords(h: Uint8Array): string[] {
  if (h.length !== 32) {
    throw new Error('Handshake hash h must be exactly 32 bytes');
  }

  const sasBytes = expand(sha256, h, 'ANONSHARE-v1-SAS-VERIFICATION', 9);
  const indices: number[] = [];

  let bitPos = 0;
  for (let i = 0; i < 6; i++) {
    let val = 0;
    for (let b = 0; b < 11; b++) {
      const byteIdx = Math.floor(bitPos / 8);
      const bitIdx = 7 - (bitPos % 8); // Big-endian MSB first
      const bit = (sasBytes[byteIdx] >> bitIdx) & 1;
      val = (val << 1) | bit;
      bitPos++;
    }
    indices.push(val);
  }

  return indices.map((idx) => BIP39_ITALIAN[idx]);
}

/**
 * Formats 6 SAS words as "w1 - w2 - w3 - w4 - w5 - w6".
 */
export function formatSasWords(words: string[]): string {
  return words.join(' - ');
}

/**
 * Computes commitment H = SHA256(salt || cleanFileBytes) per Section 5.
 */
export function calculateFileCommitment(
  salt: Uint8Array,
  cleanFileBytes: Uint8Array
): Uint8Array {
  if (salt.length !== 32) {
    throw new Error('Salt must be exactly 32 bytes');
  }
  const combined = new Uint8Array(salt.length + cleanFileBytes.length);
  combined.set(salt, 0);
  combined.set(cleanFileBytes, salt.length);
  return sha256(combined);
}

/**
 * Generates an RFC 4122 compliant UUID v4 with full cryptographic randomness.
 * Uses crypto.randomUUID() if available (Secure Contexts), and falls back to
 * crypto.getRandomValues() (guaranteed by W3C in both Secure and Non-Secure Contexts,
 * including LAN HTTP origins like 192.168.x.x).
 */
export function generateUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  // Cryptographically secure fallback using getRandomValues (available in all contexts)
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    // Set UUID version to 4 (0100xxxx) in byte 6
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set UUID variant to RFC 4122 (10xxxxxx) in byte 8
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }

  // Ultra-safe pseudo-random fallback (should never occur in modern browsers)
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Universal clipboard copy supporting non-secure contexts (LAN HTTP).
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {}
  }

  // Fallback for non-secure contexts (HTTP LAN) using document.execCommand
  try {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textArea);
    return ok;
  } catch {
    return false;
  }
}

