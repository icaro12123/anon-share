import { sha256 } from '@noble/hashes/sha256';
import { NoiseSession } from '../crypto/noise.ts';
import { toHex } from '../crypto/keys.ts';
import {
  NostrIdentity,
  NostrRelayPool,
  NostrEvent,
  bytesToBase64,
  base64ToBytes,
  NOSTR_EPHEMERAL_KIND
} from './nostr.ts';

export const MSG_TYPE_CONTROL = 0x01;

export interface ControlEnvelope {
  seq: number;
  type: 'SAS_CONFIRMED' | 'SDP_OFFER' | 'SDP_ANSWER' | 'DC_READY';
  payload?: any;
}

export type MessageHandler = (envelope: ControlEnvelope) => void;

interface BufferedMessage {
  ciphertext: Uint8Array;
  receivedAt: number;
}

/**
 * Handles Section 3.2b post-handshake transport over Nostr:
 * - Deterministic sequence numbers (seq) inside encrypted plaintext
 * - Ciphertext deduplication
 * - Retransmission of identical ciphertext bytes
 * - Reorder buffer (10 seconds window)
 * - Safe candidate decryption (Noise counter does not advance on failure)
 */
export class NostrPostHandshakeTransport {
  private readonly roomTag: string;
  private readonly pool: NostrRelayPool;
  private readonly identity: NostrIdentity;
  private readonly noiseSession: NoiseSession;
  private readonly subscriptionId: string;

  private outgoingSeq: number = 0;
  private incomingSeq: number = 0;

  private seenCiphertextHashes: Set<string> = new Set();
  private reorderBuffer: BufferedMessage[] = [];
  private readonly REORDER_TTL_MS = 10000; // 10 seconds buffer window

  private pendingOutgoing: {
    envelope: ControlEnvelope;
    ciphertext: Uint8Array;
    timer: ReturnType<typeof setInterval> | null;
  } | null = null;

  private onMessageCallback?: MessageHandler;
  private isClosed: boolean = false;

  constructor(options: {
    roomTag: string;
    pool: NostrRelayPool;
    identity: NostrIdentity;
    noiseSession: NoiseSession;
    onMessage?: MessageHandler;
  }) {
    this.roomTag = options.roomTag;
    this.pool = options.pool;
    this.identity = options.identity;
    this.noiseSession = options.noiseSession;
    this.onMessageCallback = options.onMessage;
    this.subscriptionId = `post_${Math.random().toString(36).substring(2, 10)}`;

    this.subscribe();
  }

  private subscribe(): void {
    this.pool.subscribe(
      this.subscriptionId,
      {
        kinds: [NOSTR_EPHEMERAL_KIND],
        '#d': [this.roomTag]
      },
      (event) => this.handleNostrEvent(event)
    );
  }

  public setOnMessage(callback: MessageHandler): void {
    this.onMessageCallback = callback;
  }

  /**
   * Encrypts and sends a control message, retransmitting identical ciphertext until stopped or acked.
   */
  public send(
    type: ControlEnvelope['type'],
    payload?: any,
    retransmit: boolean = true
  ): void {
    if (this.isClosed) return;

    // Clear previous pending retransmission if any
    this.clearPendingOutgoing();

    const envelope: ControlEnvelope = {
      seq: this.outgoingSeq++,
      type,
      payload
    };

    // Serialize: Byte 0 = 0x01 (CONTROL), Bytes 1..N = UTF-8 JSON
    const jsonStr = JSON.stringify(envelope);
    const jsonBytes = new TextEncoder().encode(jsonStr);
    const plaintext = new Uint8Array(1 + jsonBytes.length);
    plaintext[0] = MSG_TYPE_CONTROL;
    plaintext.set(jsonBytes, 1);

    // Encrypt ONCE with Noise send cipher
    const ciphertext = this.noiseSession.encrypt(plaintext);

    // Initial publish
    this.publishCiphertext(ciphertext);

    if (retransmit) {
      const timer = setInterval(() => {
        if (!this.isClosed && this.pendingOutgoing) {
          // Re-publish identical ciphertext in fresh Nostr event
          this.publishCiphertext(this.pendingOutgoing.ciphertext);
        }
      }, 2000);

      this.pendingOutgoing = { envelope, ciphertext, timer };
    }
  }

  /**
   * Stops retransmission for the current pending message.
   */
  public clearPendingOutgoing(): void {
    if (this.pendingOutgoing?.timer) {
      clearInterval(this.pendingOutgoing.timer);
    }
    this.pendingOutgoing = null;
  }

  private publishCiphertext(ciphertext: Uint8Array): void {
    const content = bytesToBase64(ciphertext);
    const event = this.identity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', this.roomTag]],
      content
    );
    this.pool.publish(event);
  }

  private handleNostrEvent(event: NostrEvent): void {
    if (this.isClosed) return;

    // Echo filter
    if (event.pubkey === this.identity.publicKeyHex) {
      return;
    }

    let ciphertext: Uint8Array;
    try {
      ciphertext = base64ToBytes(event.content);
    } catch {
      return;
    }

    // Ignore 48-byte messages (those are handshake messages)
    if (ciphertext.length <= 48) {
      return;
    }

    // Deduplication via SHA-256 hash of ciphertext
    const hash = toHex(sha256(ciphertext));
    if (this.seenCiphertextHashes.has(hash)) {
      return;
    }
    this.seenCiphertextHashes.add(hash);

    this.processOrBufferCiphertext(ciphertext);
  }

  private processOrBufferCiphertext(ciphertext: Uint8Array): void {
    // Attempt candidate decryption without corrupting the main recvCipher state if it fails
    const candidateRecvCipher = this.noiseSession.recvCipher.clone();
    let plaintext: Uint8Array;
    try {
      plaintext = candidateRecvCipher.decryptWithAd(new Uint8Array(0), ciphertext);
    } catch {
      // Decryption failed: either corrupted or not next in sequence
      // Buffer if within TTL
      this.reorderBuffer.push({ ciphertext, receivedAt: Date.now() });
      this.cleanReorderBuffer();
      return;
    }

    // Verify CONTROL type
    if (plaintext.length < 1 || plaintext[0] !== MSG_TYPE_CONTROL) {
      return;
    }

    let envelope: ControlEnvelope;
    try {
      const jsonStr = new TextDecoder().decode(plaintext.slice(1));
      envelope = JSON.parse(jsonStr) as ControlEnvelope;
    } catch {
      return;
    }

    // Check sequence
    if (envelope.seq === this.incomingSeq) {
      // Commit cipher state
      this.noiseSession.recvCipher.decryptWithAd(new Uint8Array(0), ciphertext);
      this.incomingSeq++;
      this.onMessageCallback?.(envelope);

      // Check if buffered messages can now be processed
      this.drainReorderBuffer();
    } else if (envelope.seq > this.incomingSeq) {
      // Arrived early: buffer for up to 10s
      this.reorderBuffer.push({ ciphertext, receivedAt: Date.now() });
      this.cleanReorderBuffer();
    }
    // If envelope.seq < this.incomingSeq: old duplicate, ignore
  }

  private drainReorderBuffer(): void {
    this.cleanReorderBuffer();
    let progress = true;

    while (progress) {
      progress = false;
      for (let i = 0; i < this.reorderBuffer.length; i++) {
        const item = this.reorderBuffer[i];
        const candidateCipher = this.noiseSession.recvCipher.clone();
        try {
          const pt = candidateCipher.decryptWithAd(new Uint8Array(0), item.ciphertext);
          if (pt.length >= 1 && pt[0] === MSG_TYPE_CONTROL) {
            const env = JSON.parse(new TextDecoder().decode(pt.slice(1))) as ControlEnvelope;
            if (env.seq === this.incomingSeq) {
              // Successfully matches next sequence!
              this.noiseSession.recvCipher.decryptWithAd(new Uint8Array(0), item.ciphertext);
              this.incomingSeq++;
              this.reorderBuffer.splice(i, 1);
              this.onMessageCallback?.(env);
              progress = true;
              break;
            }
          }
        } catch {
          // Keep in buffer
        }
      }
    }
  }

  private cleanReorderBuffer(): void {
    const now = Date.now();
    this.reorderBuffer = this.reorderBuffer.filter(
      (item) => now - item.receivedAt < this.REORDER_TTL_MS
    );
  }

  public close(): void {
    this.isClosed = true;
    this.clearPendingOutgoing();
    this.pool.unsubscribe(this.subscriptionId);
    this.reorderBuffer = [];
    this.seenCiphertextHashes.clear();
  }
}
