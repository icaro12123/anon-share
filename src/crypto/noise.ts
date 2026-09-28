import { x25519 } from '@noble/curves/ed25519';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

export const NOISE_PROTOCOL_NAME = 'Noise_NNpsk0_25519_ChaChaPoly_SHA256';
export const NOISE_PROLOGUE_DIRECT = 'ANONSHARE-v1-DIRECT';
export const NOISE_PROLOGUE_TOR = 'ANONSHARE-v1-TOR';

/**
 * Noise HKDF implementation using HMAC-SHA256.
 */
export function hkdfNoise(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array,
  numOutputs: 1 | 2 | 3
): Uint8Array[] {
  const prk = hmac(sha256, chainingKey, inputKeyMaterial);
  const out1 = hmac(sha256, prk, new Uint8Array([1]));
  if (numOutputs === 1) return [out1];

  const buf2 = new Uint8Array(out1.length + 1);
  buf2.set(out1, 0);
  buf2[out1.length] = 2;
  const out2 = hmac(sha256, prk, buf2);
  if (numOutputs === 2) return [out1, out2];

  const buf3 = new Uint8Array(out2.length + 1);
  buf3.set(out2, 0);
  buf3[out2.length] = 3;
  const out3 = hmac(sha256, prk, buf3);
  return [out1, out2, out3];
}

/**
 * Noise CipherState maintaining a 32-byte key and a 64-bit nonce.
 */
export class CipherState {
  private key: Uint8Array | null;
  private nonce: bigint;

  constructor(key: Uint8Array | null = null, nonce: bigint = 0n) {
    this.key = key ? new Uint8Array(key) : null;
    this.nonce = nonce;
  }

  public hasKey(): boolean {
    return this.key !== null;
  }

  public getNonce(): bigint {
    return this.nonce;
  }

  public clone(): CipherState {
    return new CipherState(this.key, this.nonce);
  }

  private getNonceBytes(): Uint8Array {
    // RFC 7539 / Noise spec: 12-byte nonce (4 zero bytes followed by 8-byte little-endian nonce)
    const buf = new Uint8Array(12);
    let temp = this.nonce;
    for (let i = 4; i < 12; i++) {
      buf[i] = Number(temp & 0xffn);
      temp >>= 8n;
    }
    return buf;
  }

  public encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.key) {
      return new Uint8Array(plaintext);
    }
    if (this.nonce >= 0xffffffffffffffffn) {
      throw new Error('Noise nonce counter exhaustion (2^64-1)');
    }
    const cipher = chacha20poly1305(this.key, this.getNonceBytes(), ad);
    const ciphertext = cipher.encrypt(plaintext);
    this.nonce++;
    return ciphertext;
  }

  public decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.key) {
      return new Uint8Array(ciphertext);
    }
    if (this.nonce >= 0xffffffffffffffffn) {
      throw new Error('Noise nonce counter exhaustion (2^64-1)');
    }
    const cipher = chacha20poly1305(this.key, this.getNonceBytes(), ad);
    const plaintext = cipher.decrypt(ciphertext);
    this.nonce++;
    return plaintext;
  }
}

/**
 * Noise SymmetricState maintaining chaining key `ck`, handshake hash `h`, and a `CipherState`.
 */
export class SymmetricState {
  public h: Uint8Array;
  public ck: Uint8Array;
  public cipherState: CipherState;

  constructor(protocolName: string = NOISE_PROTOCOL_NAME) {
    const enc = new TextEncoder();
    const nameBytes = enc.encode(protocolName);
    if (nameBytes.length <= 32) {
      this.h = new Uint8Array(32);
      this.h.set(nameBytes, 0);
    } else {
      this.h = sha256(nameBytes);
    }
    this.ck = new Uint8Array(this.h);
    this.cipherState = new CipherState();
  }

  public clone(): SymmetricState {
    const copy = Object.create(SymmetricState.prototype);
    copy.h = new Uint8Array(this.h);
    copy.ck = new Uint8Array(this.ck);
    copy.cipherState = this.cipherState.clone();
    return copy;
  }

  public mixKey(inputKeyMaterial: Uint8Array): void {
    const [newCk, tempK] = hkdfNoise(this.ck, inputKeyMaterial, 2);
    this.ck = newCk;
    this.cipherState = new CipherState(tempK);
  }

  public mixHash(data: Uint8Array): void {
    const combined = new Uint8Array(this.h.length + data.length);
    combined.set(this.h, 0);
    combined.set(data, this.h.length);
    this.h = sha256(combined);
  }

  public mixKeyAndHash(inputKeyMaterial: Uint8Array): void {
    const [newCk, tempH, tempK] = hkdfNoise(this.ck, inputKeyMaterial, 3);
    this.ck = newCk;
    this.mixHash(tempH);
    this.cipherState = new CipherState(tempK);
  }

  public encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ciphertext = this.cipherState.encryptWithAd(this.h, plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  public decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const plaintext = this.cipherState.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }

  public split(): { h: Uint8Array; c1: CipherState; c2: CipherState } {
    const [k1, k2] = hkdfNoise(this.ck, new Uint8Array(0), 2);
    return {
      h: new Uint8Array(this.h),
      c1: new CipherState(k1),
      c2: new CipherState(k2),
    };
  }
}

export interface NoiseHandshakeResult {
  h: Uint8Array;
  c1: CipherState; // Bob -> Alice (Initiator -> Responder)
  c2: CipherState; // Alice -> Bob (Responder -> Initiator)
}

/**
 * Handshake state machine for Noise_NNpsk0_25519_ChaChaPoly_SHA256.
 *
 * Pattern:
 *   -> psk
 *   -> e
 *   <- e, ee
 */
export class NoiseHandshakeState {
  public isInitiator: boolean;
  public symmetricState: SymmetricState;
  public ephemeralPrivateKey: Uint8Array | null = null;
  public ephemeralPublicKey: Uint8Array | null = null;
  public remoteEphemeralPublicKey: Uint8Array | null = null;
  public isComplete: boolean = false;

  constructor(
    isInitiator: boolean,
    psk: Uint8Array,
    prologue: string = NOISE_PROLOGUE_DIRECT,
    ephemeralKeyPair?: { privateKey: Uint8Array; publicKey: Uint8Array }
  ) {
    if (psk.length !== 32) {
      throw new Error('PSK must be exactly 32 bytes');
    }
    this.isInitiator = isInitiator;
    this.symmetricState = new SymmetricState(NOISE_PROTOCOL_NAME);

    // Mix prologue
    const prologueBytes = new TextEncoder().encode(prologue);
    this.symmetricState.mixHash(prologueBytes);

    // MixKeyAndHash(psk)
    this.symmetricState.mixKeyAndHash(psk);

    if (ephemeralKeyPair) {
      this.ephemeralPrivateKey = ephemeralKeyPair.privateKey;
      this.ephemeralPublicKey = ephemeralKeyPair.publicKey;
    }
  }

  public clone(): NoiseHandshakeState {
    const copy = Object.create(NoiseHandshakeState.prototype);
    copy.isInitiator = this.isInitiator;
    copy.symmetricState = this.symmetricState.clone();
    copy.ephemeralPrivateKey = this.ephemeralPrivateKey ? new Uint8Array(this.ephemeralPrivateKey) : null;
    copy.ephemeralPublicKey = this.ephemeralPublicKey ? new Uint8Array(this.ephemeralPublicKey) : null;
    copy.remoteEphemeralPublicKey = this.remoteEphemeralPublicKey ? new Uint8Array(this.remoteEphemeralPublicKey) : null;
    copy.isComplete = this.isComplete;
    return copy;
  }

  /**
   * Initiator writes message 1: returns 48 bytes (32B ephemeral pubkey + 16B Poly1305 tag).
   */
  public writeMessage1(): Uint8Array {
    if (!this.isInitiator) {
      throw new Error('Only initiator can write message 1');
    }
    if (!this.ephemeralPrivateKey || !this.ephemeralPublicKey) {
      this.ephemeralPrivateKey = x25519.utils.randomPrivateKey();
      this.ephemeralPublicKey = x25519.getPublicKey(this.ephemeralPrivateKey);
    }

    this.symmetricState.mixHash(this.ephemeralPublicKey);
    // Payload is empty (0 bytes) -> produces 16 byte Poly1305 tag
    const ciphertext = this.symmetricState.encryptAndHash(new Uint8Array(0));

    const message = new Uint8Array(32 + ciphertext.length);
    message.set(this.ephemeralPublicKey, 0);
    message.set(ciphertext, 32);
    return message;
  }

  /**
   * Responder reads message 1 (must be exactly 48 bytes) and verifies AEAD tag.
   */
  public readMessage1(message: Uint8Array): void {
    if (this.isInitiator) {
      throw new Error('Only responder can read message 1');
    }
    if (message.length !== 48) {
      throw new Error(`Message 1 must be exactly 48 bytes, got ${message.length}`);
    }

    const remotePub = message.slice(0, 32);
    this.symmetricState.mixHash(remotePub);
    this.remoteEphemeralPublicKey = remotePub;

    // Decrypts and verifies AEAD tag
    const payload = this.symmetricState.decryptAndHash(message.slice(32));
    if (payload.length !== 0) {
      throw new Error('Message 1 payload must be empty');
    }
  }

  /**
   * Responder writes message 2: returns 48 bytes (32B ephemeral pubkey + 16B Poly1305 tag).
   * Also completes the handshake and produces Split().
   */
  public writeMessage2(): { message: Uint8Array; result: NoiseHandshakeResult } {
    if (this.isInitiator) {
      throw new Error('Only responder can write message 2');
    }
    if (!this.remoteEphemeralPublicKey) {
      throw new Error('Cannot write message 2 before reading message 1');
    }

    if (!this.ephemeralPrivateKey || !this.ephemeralPublicKey) {
      this.ephemeralPrivateKey = x25519.utils.randomPrivateKey();
      this.ephemeralPublicKey = x25519.getPublicKey(this.ephemeralPrivateKey);
    }

    // e
    this.symmetricState.mixHash(this.ephemeralPublicKey);

    // ee: DH(e.private, re.public)
    const dh = x25519.getSharedSecret(this.ephemeralPrivateKey, this.remoteEphemeralPublicKey);
    this.symmetricState.mixKey(dh);

    // Encrypt empty payload -> 16 bytes auth tag
    const ciphertext = this.symmetricState.encryptAndHash(new Uint8Array(0));
    const message = new Uint8Array(32 + ciphertext.length);
    message.set(this.ephemeralPublicKey, 0);
    message.set(ciphertext, 32);

    this.isComplete = true;
    const result = this.symmetricState.split();
    return { message, result };
  }

  /**
   * Initiator reads message 2 (must be exactly 48 bytes), completes handshake, and produces Split().
   */
  public readMessage2(message: Uint8Array): NoiseHandshakeResult {
    if (!this.isInitiator) {
      throw new Error('Only initiator can read message 2');
    }
    if (!this.ephemeralPrivateKey) {
      throw new Error('Cannot read message 2 before writing message 1');
    }
    if (message.length !== 48) {
      throw new Error(`Message 2 must be exactly 48 bytes, got ${message.length}`);
    }

    const remotePub = message.slice(0, 32);
    this.symmetricState.mixHash(remotePub);
    this.remoteEphemeralPublicKey = remotePub;

    // ee: DH(e.private, re.public)
    const dh = x25519.getSharedSecret(this.ephemeralPrivateKey, remotePub);
    this.symmetricState.mixKey(dh);

    // Decrypt and verify AEAD tag
    const payload = this.symmetricState.decryptAndHash(message.slice(32));
    if (payload.length !== 0) {
      throw new Error('Message 2 payload must be empty');
    }

    this.isComplete = true;
    return this.symmetricState.split();
  }
}

/**
 * Noise directional transport wrapper.
 * On Initiator (Bob): sendCipher = c1, recvCipher = c2
 * On Responder (Alice): sendCipher = c2, recvCipher = c1
 */
export class NoiseSession {
  public readonly isInitiator: boolean;
  public readonly h: Uint8Array;
  public readonly sendCipher: CipherState;
  public readonly recvCipher: CipherState;

  constructor(isInitiator: boolean, result: NoiseHandshakeResult) {
    this.isInitiator = isInitiator;
    this.h = result.h;
    if (isInitiator) {
      // Bob sends on c1 (Bob->Alice) and receives on c2 (Alice->Bob)
      this.sendCipher = result.c1;
      this.recvCipher = result.c2;
    } else {
      // Alice sends on c2 (Alice->Bob) and receives on c1 (Bob->Alice)
      this.sendCipher = result.c2;
      this.recvCipher = result.c1;
    }
  }

  public encrypt(plaintext: Uint8Array, ad: Uint8Array = new Uint8Array(0)): Uint8Array {
    return this.sendCipher.encryptWithAd(ad, plaintext);
  }

  public decrypt(ciphertext: Uint8Array, ad: Uint8Array = new Uint8Array(0)): Uint8Array {
    return this.recvCipher.decryptWithAd(ad, ciphertext);
  }
}
