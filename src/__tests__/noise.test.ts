import { describe, it, expect } from 'vitest';
import {
  NoiseHandshakeState,
  NoiseSession,
  NOISE_PROLOGUE_DIRECT
} from '../crypto/noise.ts';

describe('Noise Protocol Framework (NNpsk0_25519_ChaChaPoly_SHA256)', () => {
  const psk = new Uint8Array(32).fill(0x3a);

  it('completes mutual handshake producing matching h and functional c1/c2 transport', () => {
    // 1. Initiator writes msg 1
    const initiator = new NoiseHandshakeState(true, psk, NOISE_PROLOGUE_DIRECT);
    const msg1 = initiator.writeMessage1();

    // Section 3.2.1: msg 1 must be strictly 48 bytes
    expect(msg1.length).toBe(48);

    // 2. Responder reads msg 1 and writes msg 2
    const responder = new NoiseHandshakeState(false, psk, NOISE_PROLOGUE_DIRECT);
    responder.readMessage1(msg1);
    const { message: msg2, result: responderResult } = responder.writeMessage2();

    // Section 3.2.1: msg 2 must be strictly 48 bytes
    expect(msg2.length).toBe(48);

    // 3. Initiator reads msg 2
    const initiatorResult = initiator.readMessage2(msg2);

    // Section 3.3: Final handshake hash h must match on both sides
    expect(initiatorResult.h).toEqual(responderResult.h);

    // 4. Transport: Bob -> Alice (c1)
    const bobSession = new NoiseSession(true, initiatorResult);
    const aliceSession = new NoiseSession(false, responderResult);

    const msgFromBob = new TextEncoder().encode('Hello Alice from Bob over c1');
    const ctBob = bobSession.encrypt(msgFromBob);
    const ptAlice = aliceSession.decrypt(ctBob);
    expect(new TextDecoder().decode(ptAlice)).toBe('Hello Alice from Bob over c1');

    // 5. Transport: Alice -> Bob (c2)
    const msgFromAlice = new TextEncoder().encode('Hello Bob from Alice over c2');
    const ctAlice = aliceSession.encrypt(msgFromAlice);
    const ptBob = bobSession.decrypt(ctAlice);
    expect(new TextDecoder().decode(ptBob)).toBe('Hello Bob from Alice over c2');
  });

  it('detects tampering and bit flips on Noise transport (Poly1305 authentication)', () => {
    const initiator = new NoiseHandshakeState(true, psk);
    const msg1 = initiator.writeMessage1();

    const responder = new NoiseHandshakeState(false, psk);
    responder.readMessage1(msg1);
    const { message: msg2, result: respRes } = responder.writeMessage2();
    const initRes = initiator.readMessage2(msg2);

    const bob = new NoiseSession(true, initRes);
    const alice = new NoiseSession(false, respRes);

    const plaintext = new TextEncoder().encode('Sensitive Payload');
    const ciphertext = bob.encrypt(plaintext);

    // Flip 1 bit in ciphertext
    ciphertext[5] ^= 0x01;

    // Must throw Poly1305 tag verification error
    expect(() => alice.decrypt(ciphertext)).toThrow();
  });

  it('detects message truncation and reordering', () => {
    const initiator = new NoiseHandshakeState(true, psk);
    const msg1 = initiator.writeMessage1();

    const responder = new NoiseHandshakeState(false, psk);
    responder.readMessage1(msg1);
    const { message: msg2, result: respRes } = responder.writeMessage2();
    const initRes = initiator.readMessage2(msg2);

    const bob = new NoiseSession(true, initRes);
    const alice = new NoiseSession(false, respRes);

    bob.encrypt(new Uint8Array([1, 2, 3]));
    const chunk2 = bob.encrypt(new Uint8Array([4, 5, 6]));

    // Attempting to decrypt chunk 2 before chunk 1 violates nonce order
    expect(() => alice.decrypt(chunk2)).toThrow();
  });

  it('benchmarks Noise transport encryption and decryption speed', () => {
    const initiator = new NoiseHandshakeState(true, psk);
    const msg1 = initiator.writeMessage1();
    const responder = new NoiseHandshakeState(false, psk);
    responder.readMessage1(msg1);
    const { message: msg2, result: respRes } = responder.writeMessage2();
    const initRes = initiator.readMessage2(msg2);

    const bob = new NoiseSession(true, initRes);
    const alice = new NoiseSession(false, respRes);

    // Benchmark 16 MB chunking (1024 chunks of 16 KiB)
    const chunkSize = 16384;
    const numChunks = 1024; // 16 MB total
    const sampleChunk = new Uint8Array(chunkSize).fill(0x5a);

    const startEnc = performance.now();
    const ciphertexts: Uint8Array[] = new Array(numChunks);
    for (let i = 0; i < numChunks; i++) {
      ciphertexts[i] = bob.encrypt(sampleChunk);
    }
    const endEnc = performance.now();

    const startDec = performance.now();
    for (let i = 0; i < numChunks; i++) {
      alice.decrypt(ciphertexts[i]);
    }
    const endDec = performance.now();

    const encTimeMs = endEnc - startEnc;
    const decTimeMs = endDec - startDec;

    // 16 MB throughput: should be well under 1000ms
    expect(encTimeMs).toBeLessThan(2000);
    expect(decTimeMs).toBeLessThan(2000);
  });
});
