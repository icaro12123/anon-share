import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { toHex } from '../crypto/keys.ts';

export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
  'wss://nostr.mom'
];

export const NOSTR_EPHEMERAL_KIND = 20001;

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface NostrFilter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  '#d'?: string[];
  since?: number;
  until?: number;
  limit?: number;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export class NostrIdentity {
  public readonly privateKey: Uint8Array;
  public readonly publicKey: Uint8Array;
  public readonly publicKeyHex: string;

  constructor(privateKey?: Uint8Array) {
    this.privateKey = privateKey ?? schnorr.utils.randomPrivateKey();
    this.publicKey = schnorr.getPublicKey(this.privateKey);
    this.publicKeyHex = toHex(this.publicKey);
  }

  public signEvent(kind: number, tags: string[][], content: string, createdAt?: number): NostrEvent {
    const created_at = createdAt ?? Math.floor(Date.now() / 1000);
    const serialized = JSON.stringify([0, this.publicKeyHex, created_at, kind, tags, content]);
    const idBytes = sha256(new TextEncoder().encode(serialized));
    const id = toHex(idBytes);
    const sigBytes = schnorr.sign(idBytes, this.privateKey);
    const sig = toHex(sigBytes);

    return {
      id,
      pubkey: this.publicKeyHex,
      created_at,
      kind,
      tags,
      content,
      sig
    };
  }
}

export type EventCallback = (event: NostrEvent, relayUrl: string) => void;

export class NostrRelayPool {
  private relayUrls: string[];
  private sockets: Map<string, WebSocket> = new Map();
  private subscriptions: Map<string, { filter: NostrFilter; callback: EventCallback }> = new Map();
  private isClosed: boolean = false;
  private onStatusChange?: (relayUrl: string, status: 'connected' | 'disconnected' | 'error') => void;

  constructor(
    relays: string[] = DEFAULT_RELAYS,
    onStatusChange?: (relayUrl: string, status: 'connected' | 'disconnected' | 'error') => void
  ) {
    this.relayUrls = [...relays];
    this.onStatusChange = onStatusChange;
  }

  public connect(): void {
    if (this.isClosed) return;

    for (const url of this.relayUrls) {
      if (this.sockets.has(url)) continue;
      this.initRelay(url);
    }
  }

  private initRelay(url: string): void {
    try {
      const ws = new WebSocket(url);
      this.sockets.set(url, ws);

      ws.onopen = () => {
        if (this.isClosed) {
          ws.close();
          return;
        }
        this.onStatusChange?.(url, 'connected');
        // Resubscribe to existing active subscriptions
        for (const [subId, { filter }] of this.subscriptions.entries()) {
          this.sendToSocket(ws, ['REQ', subId, filter]);
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (!Array.isArray(msg)) return;
          const type = msg[0];

          if (type === 'EVENT' && msg.length >= 3) {
            const subId = msg[1];
            const nostrEvent = msg[2] as NostrEvent;
            const sub = this.subscriptions.get(subId);
            if (sub) {
              sub.callback(nostrEvent, url);
            }
          }
        } catch {
          // Ignore malformed JSON from relay
        }
      };

      ws.onerror = () => {
        this.onStatusChange?.(url, 'error');
      };

      ws.onclose = () => {
        this.sockets.delete(url);
        this.onStatusChange?.(url, 'disconnected');
        // Auto-reconnect after delay if pool not closed
        if (!this.isClosed) {
          setTimeout(() => {
            if (!this.isClosed && !this.sockets.has(url)) {
              this.initRelay(url);
            }
          }, 3000);
        }
      };
    } catch {
      this.onStatusChange?.(url, 'error');
    }
  }

  private sendToSocket(ws: WebSocket, payload: unknown): void {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(payload));
    }
  }

  public subscribe(subId: string, filter: NostrFilter, callback: EventCallback): void {
    this.subscriptions.set(subId, { filter, callback });
    for (const ws of this.sockets.values()) {
      this.sendToSocket(ws, ['REQ', subId, filter]);
    }
  }

  public unsubscribe(subId: string): void {
    this.subscriptions.delete(subId);
    for (const ws of this.sockets.values()) {
      this.sendToSocket(ws, ['CLOSE', subId]);
    }
  }

  public publish(event: NostrEvent): void {
    const payload = ['EVENT', event];
    for (const ws of this.sockets.values()) {
      this.sendToSocket(ws, payload);
    }
  }

  public getConnectedRelaysCount(): number {
    let count = 0;
    for (const ws of this.sockets.values()) {
      if (ws.readyState === WebSocket.OPEN) {
        count++;
      }
    }
    return count;
  }

  public close(): void {
    this.isClosed = true;
    for (const [subId] of this.subscriptions) {
      for (const ws of this.sockets.values()) {
        this.sendToSocket(ws, ['CLOSE', subId]);
      }
    }
    this.subscriptions.clear();
    for (const ws of this.sockets.values()) {
      try {
        ws.close();
      } catch {
        // Ignore close errors
      }
    }
    this.sockets.clear();
  }
}
