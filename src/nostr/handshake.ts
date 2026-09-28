import {
  NoiseHandshakeState,
  NoiseHandshakeResult,
  NOISE_PROLOGUE_DIRECT
} from '../crypto/noise.ts';
import {
  NostrIdentity,
  NostrRelayPool,
  NostrEvent,
  bytesToBase64,
  base64ToBytes,
  NOSTR_EPHEMERAL_KIND
} from './nostr.ts';

export type HandshakeStatus =
  | 'idle'
  | 'listening'
  | 'initiating'
  | 'in_session'
  | 'completed'
  | 'timeout'
  | 'error';

export interface HandshakeCache {
  eB: Uint8Array;
  msg2Bytes: Uint8Array;
  lastSentTime: number;
}

/**
 * Handles the Section 3.2 Anti-DoS Noise NNpsk0 handshake over Nostr.
 */
export class NostrHandshakeManager {
  private readonly isInitiator: boolean;
  private readonly psk: Uint8Array;
  private readonly roomTag: string;
  private readonly pool: NostrRelayPool;
  private readonly identity: NostrIdentity;
  private readonly prologue: string;

  private activeHandshakeState: NoiseHandshakeState | null = null;
  private status: HandshakeStatus = 'idle';
  private subscriptionId: string;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryStartTime: number = 0;
  private readonly MAX_RETRY_DURATION_MS = 60000; // 60 seconds max retry
  private readonly RETRY_INTERVAL_MS = 3000; // 3 seconds base retry

  // Alice responder cache
  private responderCache: HandshakeCache | null = null;
  private onHandshakeComplete?: (result: NoiseHandshakeResult) => void;
  private onStatusChange?: (status: HandshakeStatus, message?: string) => void;

  constructor(options: {
    isInitiator: boolean;
    psk: Uint8Array;
    roomTag: string;
    pool: NostrRelayPool;
    identity: NostrIdentity;
    prologue?: string;
    onHandshakeComplete?: (result: NoiseHandshakeResult) => void;
    onStatusChange?: (status: HandshakeStatus, message?: string) => void;
  }) {
    this.isInitiator = options.isInitiator;
    this.psk = options.psk;
    this.roomTag = options.roomTag;
    this.pool = options.pool;
    this.identity = options.identity;
    this.prologue = options.prologue ?? NOISE_PROLOGUE_DIRECT;
    this.onHandshakeComplete = options.onHandshakeComplete;
    this.onStatusChange = options.onStatusChange;
    this.subscriptionId = `sub_${Math.random().toString(36).substring(2, 10)}`;
  }

  public getStatus(): HandshakeStatus {
    return this.status;
  }

  private setStatus(status: HandshakeStatus, message?: string): void {
    this.status = status;
    this.onStatusChange?.(status, message);
  }

  public start(): void {
    if (this.status !== 'idle') return;

    // Subscribe on Nostr for the RoomTag
    this.pool.subscribe(
      this.subscriptionId,
      {
        kinds: [NOSTR_EPHEMERAL_KIND],
        '#d': [this.roomTag]
      },
      (event) => this.handleNostrEvent(event)
    );

    if (this.isInitiator) {
      this.startInitiator();
    } else {
      this.startResponder();
    }
  }

  /**
   * Alice (Responder) starts listening passivly on the roomTag.
   */
  private startResponder(): void {
    this.setStatus('listening', 'In attesa di connessione del partecipante...');
  }

  /**
   * Bob (Initiator) writes msg1 and starts retry loop.
   */
  private startInitiator(): void {
    this.setStatus('initiating', 'Invio richiesta di connessione...');
    this.activeHandshakeState = new NoiseHandshakeState(true, this.psk, this.prologue);
    const msg1Bytes = this.activeHandshakeState.writeMessage1();

    this.retryStartTime = Date.now();
    this.publishMsg1(msg1Bytes);
    this.scheduleRetry(msg1Bytes);
  }

  private publishMsg1(msg1Bytes: Uint8Array): void {
    const content = bytesToBase64(msg1Bytes);
    const event = this.identity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', this.roomTag]],
      content
    );
    this.pool.publish(event);
  }

  private scheduleRetry(msg1Bytes: Uint8Array): void {
    if (this.status !== 'initiating') return;

    if (Date.now() - this.retryStartTime > this.MAX_RETRY_DURATION_MS) {
      this.setStatus('timeout', 'Tempo scaduto per la connessione');
      this.cleanup();
      return;
    }

    // Interval 3s with jitter (+- 300ms)
    const jitter = Math.floor(Math.random() * 600) - 300;
    const interval = Math.max(1500, this.RETRY_INTERVAL_MS + jitter);

    this.retryTimer = setTimeout(() => {
      if (this.status === 'initiating') {
        // Section 3.2.4: fresh Nostr event with new timestamp and new signature, identical 48-byte payload
        this.publishMsg1(msg1Bytes);
        this.scheduleRetry(msg1Bytes);
      }
    }, interval);
  }

  private handleNostrEvent(event: NostrEvent): void {
    // Section 3.2.1: Preliminary echo and length filter
    // 1. Scarta a monte qualsiasi evento firmato con la propria chiave pubblica Nostr effimera
    if (event.pubkey === this.identity.publicKeyHex) {
      return;
    }

    // Parse payload
    let payload: Uint8Array;
    try {
      payload = base64ToBytes(event.content);
    } catch {
      return; // Invalid base64, discard
    }

    // 2. Scarta prima di qualunque operazione crittografica qualsiasi payload che non sia esattamente di 48 byte
    if (payload.length !== 48) {
      return;
    }

    if (this.isInitiator) {
      this.handleInitiatorEvent(payload);
    } else {
      this.handleResponderEvent(payload);
    }
  }

  /**
   * Alice processes incoming events (msg 1).
   */
  private handleResponderEvent(payload: Uint8Array): void {
    const now = Date.now();

    // Section 3.2.3: Resilience to msg2 loss (Cache & Retransmit)
    if ((this.status === 'in_session' || this.status === 'completed') && this.responderCache) {
      // Check if this payload has the same e_B (first 32 bytes)
      const incomingEb = payload.slice(0, 32);
      if (this.areBuffersEqual(incomingEb, this.responderCache.eB)) {
        // Rate-limit: max 1 retransmit every 1.5s
        if (now - this.responderCache.lastSentTime >= 1500) {
          this.responderCache.lastSentTime = now;
          this.sendMsg2Event(this.responderCache.msg2Bytes);
        }
      }
      // If different e_B, ignore (single-use room)
      return;
    }

    if (this.status !== 'listening') {
      return;
    }

    // Section 3.2.2: Candidate ephemeral state anti-DoS
    const candidate = new NoiseHandshakeState(false, this.psk, this.prologue);
    try {
      candidate.readMessage1(payload);
    } catch {
      // AEAD verification failed: discard silently, keep state intact
      return;
    }

    // Tag verified: commit to IN_SESSION
    this.setStatus('in_session', 'Peer autenticato, generazione risposta...');
    const { message: msg2Bytes, result } = candidate.writeMessage2();

    this.responderCache = {
      eB: new Uint8Array(candidate.remoteEphemeralPublicKey!),
      msg2Bytes,
      lastSentTime: now
    };

    this.sendMsg2Event(msg2Bytes);
    this.setStatus('completed', 'Handshake crittografico completato');
    this.onHandshakeComplete?.(result);
  }

  private sendMsg2Event(msg2Bytes: Uint8Array): void {
    const content = bytesToBase64(msg2Bytes);
    const event = this.identity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', this.roomTag]],
      content
    );
    this.pool.publish(event);
  }

  /**
   * Bob processes incoming events (msg 2).
   */
  private handleInitiatorEvent(payload: Uint8Array): void {
    if (this.status !== 'initiating' || !this.activeHandshakeState) {
      return;
    }

    // Section 3.2.2: Candidate ephemeral state anti-DoS on Bob
    const candidate = this.activeHandshakeState.clone();
    let result: NoiseHandshakeResult;
    try {
      result = candidate.readMessage2(payload);
    } catch {
      // AEAD tag failed (junk from relay): discard silently, keep activeHandshakeState and retry timer intact
      return;
    }

    // AEAD verified: commit to Split() and stop retries
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }

    this.activeHandshakeState = candidate;
    this.setStatus('completed', 'Handshake crittografico completato');
    this.onHandshakeComplete?.(result);
  }

  private areBuffersEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  public cleanup(): void {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    this.pool.unsubscribe(this.subscriptionId);
  }
}
