import { describe, it, expect } from 'vitest';
import { TransferProtocol, CompletedFile } from '../protocol/transfer.ts';
import { NoiseHandshakeState, NoiseSession } from '../crypto/noise.ts';

describe('3-Stage Transfer Protocol (Sections 5, 6, 8)', () => {
  const psk = new Uint8Array(32).fill(0x88);

  function createPairedNoiseSessions() {
    const init = new NoiseHandshakeState(true, psk);
    const resp = new NoiseHandshakeState(false, psk);

    const msg1 = init.writeMessage1();
    resp.readMessage1(msg1);
    const { message: msg2, result: respRes } = resp.writeMessage2();
    const initRes = init.readMessage2(msg2);

    const bobSession = new NoiseSession(true, initRes);
    const aliceSession = new NoiseSession(false, respRes);
    return { bobSession, aliceSession };
  }

  it('completes full bilateral exchange flow with dual consent and commitment verification', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();

    let bobCompletedFile: CompletedFile | null = null;
    let aliceCompletedFile: CompletedFile | null = null;

    let bobProtocol: TransferProtocol;
    let aliceProtocol: TransferProtocol;

    // Bob = Initiator
    bobProtocol = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => aliceProtocol.handleIncomingMessage(data),
      onFileCompleted: (f) => {
        bobCompletedFile = f;
      }
    });

    // Alice = Responder
    aliceProtocol = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bobProtocol.handleIncomingMessage(data),
      onFileCompleted: (f) => {
        aliceCompletedFile = f;
      }
    });

    // File contents
    const bobFile = new Uint8Array(50000).fill(0x42); // 50 KB
    const aliceFile = new Uint8Array(35000).fill(0x99); // 35 KB

    // Stage 1: Send Offers
    bobProtocol.prepareAndSendOffer({
      cleanBytes: bobFile,
      mime: 'image/jpeg',
      extension: 'jpg',
      declaredMax: 1024 * 1024
    });

    aliceProtocol.prepareAndSendOffer({
      cleanBytes: aliceFile,
      mime: 'image/png',
      extension: 'png',
      declaredMax: 1024 * 1024
    });

    expect(bobProtocol.getState()).toBe('both_offered');
    expect(aliceProtocol.getState()).toBe('both_offered');

    // Stage 2: Both Accept
    bobProtocol.acceptExchange();
    aliceProtocol.acceptExchange();

    // Allow async chunk processing
    await new Promise((r) => setTimeout(r, 50));

    // Stage 3 Verification: both files received, verified and completed!
    expect(bobCompletedFile).not.toBeNull();
    expect(aliceCompletedFile).not.toBeNull();

    // Bob received Alice's file
    expect(bobCompletedFile!.size).toBe(35000);
    expect(bobCompletedFile!.data).toEqual(aliceFile);
    expect(bobCompletedFile!.mime).toBe('image/png');

    // Alice received Bob's file
    expect(aliceCompletedFile!.size).toBe(50000);
    expect(aliceCompletedFile!.data).toEqual(bobFile);
    expect(aliceCompletedFile!.mime).toBe('image/jpeg');

    expect(bobProtocol.getState()).toBe('completed');
    expect(aliceProtocol.getState()).toBe('completed');
  });

  it('rejects file if byte count exceeds declared_max limit', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let errorCaught = false;

    let bobProtocol: TransferProtocol;
    let aliceProtocol: TransferProtocol;

    bobProtocol = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => aliceProtocol.handleIncomingMessage(data),
      onError: () => {
        errorCaught = true;
      }
    });

    aliceProtocol = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bobProtocol.handleIncomingMessage(data),
      onError: () => {
        errorCaught = true;
      }
    });

    // Bob declares max 1000 bytes, but actually sends 2000 bytes
    bobProtocol.prepareAndSendOffer({
      cleanBytes: new Uint8Array(2000),
      mime: 'image/jpeg',
      extension: 'jpg',
      declaredMax: 1000 // Understated declaredMax!
    });

    aliceProtocol.prepareAndSendOffer({
      cleanBytes: new Uint8Array(500),
      mime: 'image/png',
      extension: 'png',
      declaredMax: 1000
    });

    bobProtocol.acceptExchange();
    aliceProtocol.acceptExchange();

    await new Promise((r) => setTimeout(r, 50));

    // Alice must abort due to exceeding declared_max
    expect(errorCaught).toBe(true);
    expect(aliceProtocol.getState()).toBe('error');
  });

  it('rejects file if SHA-256 commitment does not match after transmission', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let errorCaught = false;

    let bobProtocol: TransferProtocol;
    let aliceProtocol: TransferProtocol;

    bobProtocol = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => aliceProtocol.handleIncomingMessage(data)
    });

    aliceProtocol = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bobProtocol.handleIncomingMessage(data),
      onError: (err) => {
        if (err.includes('commitment')) {
          errorCaught = true;
        }
      }
    });

    bobProtocol.prepareAndSendOffer({
      cleanBytes: new Uint8Array([1, 2, 3, 4]),
      mime: 'image/jpeg',
      extension: 'jpg',
      declaredMax: 1024
    });

    aliceProtocol.prepareAndSendOffer({
      cleanBytes: new Uint8Array([5, 6, 7, 8]),
      mime: 'image/jpeg',
      extension: 'jpg',
      declaredMax: 1024
    });

    // Tamper Bob's file payload after commitment has already been offered
    (bobProtocol as any).localFileBytes = new Uint8Array([9, 9, 9, 9]);

    bobProtocol.acceptExchange();
    aliceProtocol.acceptExchange();

    await new Promise((r) => setTimeout(r, 50));

    expect(errorCaught).toBe(true);
    expect(aliceProtocol.getState()).toBe('error');
  });
});
