import { describe, it, expect, vi } from 'vitest';
import {
  NostrHandshakeManager
} from '../nostr/handshake.ts';
import {
  NostrIdentity,
  NostrRelayPool,
  NostrEvent,
  bytesToBase64,
  NOSTR_EPHEMERAL_KIND
} from '../nostr/nostr.ts';
import { NoiseHandshakeState } from '../crypto/noise.ts';

// Mock NostrRelayPool for in-memory testing of Nostr messages
class MockRelayPool {
  public publishedEvents: NostrEvent[] = [];
  public subscriptions: Map<string, (event: NostrEvent) => void> = new Map();

  public subscribe(id: string, _filter: any, cb: (ev: NostrEvent) => void) {
    this.subscriptions.set(id, cb);
  }

  public unsubscribe(id: string) {
    this.subscriptions.delete(id);
  }

  public publish(event: NostrEvent) {
    this.publishedEvents.push(event);
    // Broadcast synchronously to all other subscriptions
    for (const cb of this.subscriptions.values()) {
      cb(event);
    }
  }

  public close() {
    this.subscriptions.clear();
  }
}

describe('Anti-DoS Nostr Handshake State Machine (Section 3.2)', () => {
  const psk = new Uint8Array(32).fill(0x77);
  const roomTag = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  it('completes direct handshake between Alice (Responder) and Bob (Initiator)', async () => {
    const mockPool = new MockRelayPool();
    const aliceIdentity = new NostrIdentity();
    const bobIdentity = new NostrIdentity();

    let aliceComplete = false;
    let bobComplete = false;

    // 1. Alice creates room and listens
    const aliceManager = new NostrHandshakeManager({
      isInitiator: false,
      psk,
      roomTag,
      pool: mockPool as unknown as NostrRelayPool,
      identity: aliceIdentity,
      onHandshakeComplete: () => {
        aliceComplete = true;
      }
    });
    aliceManager.start();
    expect(aliceManager.getStatus()).toBe('listening');

    // 2. Bob joins room and sends msg 1
    const bobManager = new NostrHandshakeManager({
      isInitiator: true,
      psk,
      roomTag,
      pool: mockPool as unknown as NostrRelayPool,
      identity: bobIdentity,
      onHandshakeComplete: () => {
        bobComplete = true;
      }
    });
    bobManager.start();

    expect(aliceComplete).toBe(true);
    expect(bobComplete).toBe(true);
    expect(aliceManager.getStatus()).toBe('completed');
    expect(bobManager.getStatus()).toBe('completed');

    aliceManager.cleanup();
    bobManager.cleanup();
  });

  it('Alice rejects unauthenticated junk msg 1 on candidate state without altering status', () => {
    const mockPool = new MockRelayPool();
    const aliceIdentity = new NostrIdentity();
    const attackerIdentity = new NostrIdentity();

    const aliceManager = new NostrHandshakeManager({
      isInitiator: false,
      psk,
      roomTag,
      pool: mockPool as unknown as NostrRelayPool,
      identity: aliceIdentity
    });
    aliceManager.start();
    expect(aliceManager.getStatus()).toBe('listening');

    // Attacker sends 48 bytes of random junk (invalid Poly1305 AEAD tag)
    const junkPayload = new Uint8Array(48).fill(0xff);
    const junkEvent = attackerIdentity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', roomTag]],
      bytesToBase64(junkPayload)
    );

    mockPool.publish(junkEvent);

    // Section 3.2.2: Alice must silently discard junk and stay in 'listening'
    expect(aliceManager.getStatus()).toBe('listening');

    aliceManager.cleanup();
  });

  it('Alice and Bob strictly reject payloads that are not exactly 48 bytes', () => {
    const mockPool = new MockRelayPool();
    const aliceIdentity = new NostrIdentity();
    const attackerIdentity = new NostrIdentity();

    const aliceManager = new NostrHandshakeManager({
      isInitiator: false,
      psk,
      roomTag,
      pool: mockPool as unknown as NostrRelayPool,
      identity: aliceIdentity
    });
    aliceManager.start();

    // Payload with 47 bytes
    const shortEvent = attackerIdentity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', roomTag]],
      bytesToBase64(new Uint8Array(47))
    );
    mockPool.publish(shortEvent);
    expect(aliceManager.getStatus()).toBe('listening');

    // Payload with 49 bytes
    const longEvent = attackerIdentity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', roomTag]],
      bytesToBase64(new Uint8Array(49))
    );
    mockPool.publish(longEvent);
    expect(aliceManager.getStatus()).toBe('listening');

    aliceManager.cleanup();
  });

  it('filters relay echo messages signed with own Nostr pubkey', () => {
    const mockPool = new MockRelayPool();
    const bobIdentity = new NostrIdentity();

    const bobManager = new NostrHandshakeManager({
      isInitiator: true,
      psk,
      roomTag,
      pool: mockPool as unknown as NostrRelayPool,
      identity: bobIdentity
    });
    bobManager.start();

    // Bob receives his own msg 1 reflected back by relay
    const echoEvent = mockPool.publishedEvents[0];
    expect(echoEvent.pubkey).toBe(bobIdentity.publicKeyHex);

    // Bob status should remain initiating (echo ignored)
    expect(bobManager.getStatus()).toBe('initiating');

    bobManager.cleanup();
  });

  it('Alice retransmits cached msg 2 when receiving duplicate msg 1 with same e_B', async () => {
    vi.useFakeTimers();
    const mockPool = new MockRelayPool();
    const aliceIdentity = new NostrIdentity();
    const bobIdentity = new NostrIdentity();

    const aliceManager = new NostrHandshakeManager({
      isInitiator: false,
      psk,
      roomTag,
      pool: mockPool as unknown as NostrRelayPool,
      identity: aliceIdentity
    });
    aliceManager.start();

    // Generate valid msg 1 from Bob
    const bobNoise = new NoiseHandshakeState(true, psk);
    const msg1Bytes = bobNoise.writeMessage1();

    const msg1Event = bobIdentity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', roomTag]],
      bytesToBase64(msg1Bytes)
    );

    // Alice receives msg 1 -> produces msg 2
    mockPool.publish(msg1Event);
    expect(mockPool.publishedEvents.length).toBe(2); // msg 1 + Alice msg 2
    const firstMsg2 = mockPool.publishedEvents[1];

    // Simulate Bob dropping msg 2 and retrying duplicate msg 1 after 2000ms
    vi.advanceTimersByTime(2000);

    const retryMsg1Event = bobIdentity.signEvent(
      NOSTR_EPHEMERAL_KIND,
      [['d', roomTag]],
      bytesToBase64(msg1Bytes)
    );
    mockPool.publish(retryMsg1Event);

    // Alice should re-publish cached msg 2
    expect(mockPool.publishedEvents.length).toBe(4);
    const secondMsg2 = mockPool.publishedEvents[3];
    expect(secondMsg2.content).toBe(firstMsg2.content);

    aliceManager.cleanup();
    vi.useRealTimers();
  });
});
