import { describe, it, expect } from 'vitest';
import {
  generateRoomSecret,
  deriveDirectKeys,
  deriveTorAuthKey,
  deriveSasWords,
  formatSasWords,
  calculateFileCommitment,
  toHex,
  fromHex,
  generateUUID
} from '../crypto/keys.ts';
import { BIP39_ITALIAN } from '../crypto/bip39-it.ts';

describe('Crypto & Key Derivation (Section 3.1 & 3.3)', () => {
  it('generates 32-byte cryptographically random room secret', () => {
    const s1 = generateRoomSecret();
    const s2 = generateRoomSecret();
    expect(s1.length).toBe(32);
    expect(s2.length).toBe(32);
    expect(toHex(s1)).not.toBe(toHex(s2));
  });

  it('converts to/from hex correctly', () => {
    const original = new Uint8Array([0x00, 0x0f, 0x10, 0xff, 0x42]);
    const hex = toHex(original);
    expect(hex).toBe('000f10ff42');
    const recovered = fromHex(hex);
    expect(recovered).toEqual(original);
  });

  it('derives PSK_Noise and RoomTag deterministically from S_room', () => {
    const roomSecret = new Uint8Array(32).fill(0xaa);
    const { noisePsk, roomTag } = deriveDirectKeys(roomSecret);

    expect(noisePsk.length).toBe(32);
    expect(roomTag.length).toBe(64); // 64 hex chars = 32 bytes

    // Re-derivation must produce identical keys
    const second = deriveDirectKeys(roomSecret);
    expect(toHex(noisePsk)).toBe(toHex(second.noisePsk));
    expect(roomTag).toBe(second.roomTag);
  });

  it('derives Tor HS client auth key from S_room', () => {
    const roomSecret = new Uint8Array(32).fill(0x55);
    const authKey = deriveTorAuthKey(roomSecret);
    expect(authKey.length).toBe(32);
  });

  it('derives exactly 6 SAS words from BIP-39 Italian wordlist (66-bit partition)', () => {
    const h = new Uint8Array(32).fill(0x12);
    const words = deriveSasWords(h);

    expect(words.length).toBe(6);
    for (const w of words) {
      expect(typeof w).toBe('string');
      expect(BIP39_ITALIAN).toContain(w);
    }

    const formatted = formatSasWords(words);
    expect(formatted.split(' - ').length).toBe(6);
  });

  it('computes file commitment H = SHA256(salt || cleanFileBytes)', () => {
    const salt = new Uint8Array(32).fill(0x77);
    const fileBytes = new TextEncoder().encode('Test Clean Media Content');
    const commitment = calculateFileCommitment(salt, fileBytes);

    expect(commitment.length).toBe(32);

    // Tampering file alters commitment
    const tamperedBytes = new TextEncoder().encode('Test Clean Media ContenT');
    const tamperedCommitment = calculateFileCommitment(salt, tamperedBytes);
    expect(toHex(commitment)).not.toBe(toHex(tamperedCommitment));

    // Tampering salt alters commitment
    const tamperedSalt = new Uint8Array(32).fill(0x78);
    const tamperedSaltCommitment = calculateFileCommitment(tamperedSalt, fileBytes);
    expect(toHex(commitment)).not.toBe(toHex(tamperedSaltCommitment));
  });

  it('generates valid RFC 4122 v4 UUID with cryptographic entropy', () => {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const u1 = generateUUID();
    const u2 = generateUUID();

    expect(u1).toMatch(uuidRegex);
    expect(u2).toMatch(uuidRegex);
    expect(u1).not.toBe(u2);

    // Verify 1000 UUIDs have zero collisions
    const set = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const u = generateUUID();
      expect(u).toMatch(uuidRegex);
      set.add(u);
    }
    expect(set.size).toBe(1000);
  });

  it('falls back seamlessly to getRandomValues when crypto.randomUUID is undefined (HTTP LAN)', () => {
    const original = crypto.randomUUID;
    try {
      // Simulate non-secure HTTP context where crypto.randomUUID is not a function
      (crypto as any).randomUUID = undefined;

      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      const u = generateUUID();
      expect(u).toMatch(uuidRegex);
    } finally {
      (crypto as any).randomUUID = original;
    }
  });
});

