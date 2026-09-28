import { describe, it, expect } from 'vitest';
import { TransferProtocol, CompletedFile, OfferItemPayload } from '../protocol/transfer.ts';
import { NoiseHandshakeState, NoiseSession } from '../crypto/noise.ts';
import { toHex } from '../crypto/keys.ts';
import { generateSanitizedThumbnail } from '../media/sanitize.ts';

describe('Batch Multi-Media Transfer, Byte Ceilings & Reciprocal Completion Gate', () => {
  const psk = new Uint8Array(32).fill(0x77);

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

  function makeSampleJpeg(size: number): Uint8Array {
    const bytes = new Uint8Array(size).fill(0x33);
    bytes[0] = 0xff;
    bytes[1] = 0xd8;
    bytes[2] = 0xff;
    bytes[3] = 0xe0;
    bytes[4] = 0;
    bytes[5] = 16;
    bytes[6] = 0x4a;
    bytes[7] = 0x46;
    bytes[8] = 0x49;
    bytes[9] = 0x46;
    bytes[10] = 0;
    bytes[11] = 0;
    return bytes;
  }

  function makeSamplePng(size: number): Uint8Array {
    const bytes = new Uint8Array(size).fill(0x55);
    bytes[0] = 0x89;
    bytes[1] = 0x50;
    bytes[2] = 0x4e;
    bytes[3] = 0x47;
    bytes[4] = 0x0d;
    bytes[5] = 0x0a;
    bytes[6] = 0x1a;
    bytes[7] = 0x0a;
    return bytes;
  }

  it('1. sends and receives multi-message offer with batch of 50 files and thumbnails', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let aliceReceivedOffers: OfferItemPayload[] = [];

    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    const alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onBatchOfferReceived: (items) => {
        aliceReceivedOffers = items;
      }
    });

    // Create 50 valid items with compliant thumbnails (JPEG data URLs <= 8 KB)
    const validThumbnail = 'data:image/jpeg;base64,' + 'A'.repeat(500);
    const items = Array.from({ length: 50 }, () => ({
      cleanBytes: makeSampleJpeg(100),
      mime: 'image/jpeg' as const,
      previewMode: 'thumbnail' as const,
      thumbnailDataUrl: validThumbnail,
      declaredMax: 1024
    }));

    bob.prepareAndSendBatchOffer(items);

    expect(aliceReceivedOffers.length).toBe(50);
    expect(alice.getState()).toBe('offer_received');
    expect(bob.getState()).toBe('offer_sent');
  });

  it('2. aborts if remote offer totalDeclaredMax exceeds 100 MB or count > 50', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();

    let alice: TransferProtocol;
    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data)
    });

    // Try to send batch exceeding 100 MB
    expect(() => {
      bob.prepareAndSendBatchOffer([
        {
          cleanBytes: makeSampleJpeg(100),
          mime: 'image/jpeg',
          previewMode: 'blurhash',
          declaredMax: 101 * 1024 * 1024 // 101 MB!
        }
      ]);
    }).toThrow(/100 MB/);
  });

  it('3. aborts if remote thumbnail is not JPEG or exceeds 8 KB', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let aliceError = '';

    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    const alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onError: (err) => {
        aliceError = err;
      }
    });

    // Thumbnail without proper JPEG prefix
    (bob as any).sendControlMessage('OFFER_ITEM', {
      index: 0,
      commitment: 'a'.repeat(64),
      previewMode: 'thumbnail',
      thumbnailDataUrl: 'data:image/png;base64,1234',
      declaredMax: 1024,
      mime: 'image/jpeg'
    });

    expect(aliceError).toContain('Formato miniatura non conforme');
    expect(alice.getState()).toBe('error');

    // Reset and test thumbnail > 8 KB
    const { bobSession: bob2, aliceSession: alice2 } = createPairedNoiseSessions();
    let alice2Error = '';
    const bobProto2 = new TransferProtocol({
      isInitiator: true,
      noiseSession: bob2,
      sendRawData: (data) => aliceProto2.handleIncomingMessage(data)
    });
    const aliceProto2 = new TransferProtocol({
      isInitiator: false,
      noiseSession: alice2,
      sendRawData: (data) => bobProto2.handleIncomingMessage(data),
      onError: (err) => {
        alice2Error = err;
      }
    });

    (bobProto2 as any).sendControlMessage('OFFER_ITEM', {
      index: 0,
      commitment: 'a'.repeat(64),
      previewMode: 'thumbnail',
      thumbnailDataUrl: 'data:image/jpeg;base64,' + 'A'.repeat(8200), // > 8 KB
      declaredMax: 1024,
      mime: 'image/jpeg'
    });

    expect(alice2Error).toContain('8 KB');
    expect(aliceProto2.getState()).toBe('error');
  });

  it('4. streaming byte ceiling: aborts and wipes RAM if FILE_START totalBytes > declaredMax', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let aliceError = '';

    let alice: TransferProtocol;
    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onError: (err) => {
        aliceError = err;
      }
    });

    bob.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSampleJpeg(500),
        mime: 'image/jpeg',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    alice.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSamplePng(500),
        mime: 'image/png',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    // Alice accepts
    alice.acceptExchange();

    // Bob accepts manually to Alice without trigger auto streaming
    (bob as any).sendControlMessage('BATCH_ACCEPT', {
      myCommitments: (bob as any).localBatch.map((it: any) => it.commitmentHex),
      peerCommitments: (bob as any).remoteOfferItems.map((it: any) => it.commitment)
    });

    (bob as any).sendControlMessage('BATCH_SALTS', {
      salts: (bob as any).localBatch.map((it: any) => toHex(it.salt))
    });

    // Bob maliciously sends FILE_START with totalBytes = 2000 > declaredMax 1000
    (bob as any).sendControlMessage('FILE_START', { fileIndex: 0, totalBytes: 2000 });

    expect(aliceError).toContain('supera declaredMax');
    expect(alice.getState()).toBe('error');
  });

  it('5. streaming byte ceiling: aborts and wipes RAM if cumulative DATA bytes exceed declaredMax', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let aliceError = '';

    let alice: TransferProtocol;
    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onError: (err) => {
        aliceError = err;
      }
    });

    bob.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSampleJpeg(500),
        mime: 'image/jpeg',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    alice.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSamplePng(500),
        mime: 'image/png',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    alice.acceptExchange();

    (bob as any).sendControlMessage('BATCH_ACCEPT', {
      myCommitments: (bob as any).localBatch.map((it: any) => it.commitmentHex),
      peerCommitments: (bob as any).remoteOfferItems.map((it: any) => it.commitment)
    });

    (bob as any).sendControlMessage('BATCH_SALTS', {
      salts: (bob as any).localBatch.map((it: any) => toHex(it.salt))
    });

    // Start with declared 1000 bytes
    (bob as any).sendControlMessage('FILE_START', { fileIndex: 0, totalBytes: 1000 });

    // Send DATA chunk of 1500 bytes (> 1000 declaredMax)
    const oversizedChunk = new Uint8Array(1500);
    const plaintext = new Uint8Array(3 + oversizedChunk.length);
    plaintext[0] = 0x02; // MSG_TYPE_DATA
    plaintext[1] = 0; // fileIndex MSB
    plaintext[2] = 0; // fileIndex LSB
    plaintext.set(oversizedChunk, 3);

    const ciphertext = bobSession.encrypt(plaintext);
    alice.handleIncomingMessage(ciphertext);

    expect(aliceError).toContain('superano declaredMax');
    expect(alice.getState()).toBe('error');
    // Buffer wiped in RAM
    expect((alice as any).lockedReceivedFiles.length).toBe(0);
  });

  it('6. aborts and wipes RAM if DATA chunk has invalid or out-of-order fileIndex', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let aliceError = '';

    let alice: TransferProtocol;
    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onError: (err) => {
        aliceError = err;
      }
    });

    bob.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSampleJpeg(500),
        mime: 'image/jpeg',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    alice.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSamplePng(500),
        mime: 'image/png',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    alice.acceptExchange();

    (bob as any).sendControlMessage('BATCH_ACCEPT', {
      myCommitments: (bob as any).localBatch.map((it: any) => it.commitmentHex),
      peerCommitments: (bob as any).remoteOfferItems.map((it: any) => it.commitment)
    });

    (bob as any).sendControlMessage('BATCH_SALTS', {
      salts: (bob as any).localBatch.map((it: any) => toHex(it.salt))
    });

    // Bob starts file 0
    (bob as any).sendControlMessage('FILE_START', { fileIndex: 0, totalBytes: 500 });

    // But sends DATA chunk tagged with fileIndex 1!
    const chunk = new Uint8Array(100);
    const plaintext = new Uint8Array(3 + chunk.length);
    plaintext[0] = 0x02;
    plaintext[1] = 0;
    plaintext[2] = 1; // Wrong index!
    plaintext.set(chunk, 3);

    const ciphertext = bobSession.encrypt(plaintext);
    alice.handleIncomingMessage(ciphertext);

    expect(aliceError).toContain('fileIndex non valido o fuori sequenza');
    expect(alice.getState()).toBe('error');
  });

  it('7. peer fields: rejects unsupported MIME and aborts on magic bytes mismatch', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let aliceError = '';

    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    const alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onError: (err) => {
        aliceError = err;
      }
    });

    // 1. Offer with MIME not in allowlist (e.g. application/pdf)
    (bob as any).sendControlMessage('OFFER_ITEM', {
      index: 0,
      commitment: 'a'.repeat(64),
      previewMode: 'blurhash',
      declaredMax: 1024,
      mime: 'application/pdf'
    });

    expect(aliceError).toContain('MIME type non supportato o non in allowlist');
    expect(alice.getState()).toBe('error');

    // 2. Magic bytes mismatch: declares image/jpeg but sends text/invalid bytes
    const { bobSession: bob2, aliceSession: alice2 } = createPairedNoiseSessions();
    let alice2Error = '';

    let aliceProto2: TransferProtocol;
    const bobProto2 = new TransferProtocol({
      isInitiator: true,
      noiseSession: bob2,
      sendRawData: (data) => aliceProto2.handleIncomingMessage(data)
    });

    aliceProto2 = new TransferProtocol({
      isInitiator: false,
      noiseSession: alice2,
      sendRawData: (data) => bobProto2.handleIncomingMessage(data),
      onError: (err) => {
        alice2Error = err;
      }
    });

    bobProto2.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSampleJpeg(500),
        mime: 'image/jpeg',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    aliceProto2.prepareAndSendBatchOffer([
      {
        cleanBytes: makeSamplePng(500),
        mime: 'image/png',
        previewMode: 'blurhash',
        declaredMax: 1000
      }
    ]);

    aliceProto2.acceptExchange();

    (bobProto2 as any).sendControlMessage('BATCH_ACCEPT', {
      myCommitments: (bobProto2 as any).localBatch.map((it: any) => it.commitmentHex),
      peerCommitments: (bobProto2 as any).remoteOfferItems.map((it: any) => it.commitment)
    });

    (bobProto2 as any).sendControlMessage('BATCH_SALTS', {
      salts: (bobProto2 as any).localBatch.map((it: any) => toHex(it.salt))
    });

    // Bob starts file 0 with declared JPEG
    (bobProto2 as any).sendControlMessage('FILE_START', { fileIndex: 0, totalBytes: 100 });

    // Bob sends 100 bytes of ASCII characters instead of JPEG magic
    const invalidMagicBytes = new Uint8Array(100).fill(0x61); // 'aaaa...'
    const plaintext = new Uint8Array(3 + invalidMagicBytes.length);
    plaintext[0] = 0x02;
    plaintext[1] = 0;
    plaintext[2] = 0;
    plaintext.set(invalidMagicBytes, 3);
    aliceProto2.handleIncomingMessage(bob2.encrypt(plaintext));

    // Bob sends FILE_END
    (bobProto2 as any).sendControlMessage('FILE_END', { fileIndex: 0, totalBytes: 100 });

    expect(alice2Error).toContain('Validazione magic bytes fallita');
    expect(aliceProto2.getState()).toBe('error');
  });

  it('8. completes full multi-item exchange with reciprocal gate synchronization', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();

    let bobCompletedFiles: CompletedFile[] = [];
    let aliceCompletedFiles: CompletedFile[] = [];

    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data),
      onBatchCompleted: (files) => {
        bobCompletedFiles = files;
      }
    });

    const alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onBatchCompleted: (files) => {
        aliceCompletedFiles = files;
      }
    });

    // Bob sends 2 files (1 JPEG, 1 PNG)
    const bobFile1 = makeSampleJpeg(5000);
    const bobFile2 = makeSamplePng(4000);

    // Alice sends 1 file (1 JPEG)
    const aliceFile1 = makeSampleJpeg(3000);

    bob.prepareAndSendBatchOffer([
      { cleanBytes: bobFile1, mime: 'image/jpeg', previewMode: 'blurhash', declaredMax: 10000 },
      { cleanBytes: bobFile2, mime: 'image/png', previewMode: 'thumbnail', thumbnailDataUrl: 'data:image/jpeg;base64,abc1234', declaredMax: 10000 }
    ]);

    alice.prepareAndSendBatchOffer([
      { cleanBytes: aliceFile1, mime: 'image/jpeg', previewMode: 'blurhash', declaredMax: 10000 }
    ]);

    expect(bob.getState()).toBe('both_offered');
    expect(alice.getState()).toBe('both_offered');

    bob.acceptExchange();
    alice.acceptExchange();

    await new Promise((r) => setTimeout(r, 60));

    expect(bobCompletedFiles.length).toBe(1);
    expect(aliceCompletedFiles.length).toBe(2);

    expect(bob.getState()).toBe('completed');
    expect(alice.getState()).toBe('completed');

    // Verify safe extension assignment derived from MIME allowlist (anon_..._01.jpg, anon_..._02.png)
    expect(aliceCompletedFiles[0].name).toMatch(/^anon_\d{8}_[0-9a-f]{4}_01\.jpg$/);
    expect(aliceCompletedFiles[1].name).toMatch(/^anon_\d{8}_[0-9a-f]{4}_02\.png$/);
  });

  it('9. thumbnail fallback: falls back to blurhash if thumbnail exceeds 8 KB after second pass', () => {
    // Mock canvas that produces large data URL
    const mockCanvas: any = {
      width: 100,
      height: 100,
      toDataURL: (_mime: string, _quality: number) => {
        // Return string > 8 KB
        return 'data:image/jpeg;base64,' + 'Z'.repeat(9000);
      }
    };

    const res = generateSanitizedThumbnail(mockCanvas);
    expect(res.success).toBe(false);
    expect(res.fallbackToBlurhash).toBe(true);
  });

  it('10. live offer update and blur toggle: sends OFFER_RESET, resets peer offer and consent, completes successfully', async () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let bobCompletedFiles: any[] = [];
    let aliceCompletedFiles: any[] = [];
    let aliceOffersReceived: any[] = [];

    let alice: TransferProtocol;
    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data),
      onBatchCompleted: (files) => {
        bobCompletedFiles = files;
      }
    });

    alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onBatchOfferReceived: (items) => {
        aliceOffersReceived.push(items);
      },
      onBatchCompleted: (files) => {
        aliceCompletedFiles = files;
      }
    });

    const bobFile1 = makeSampleJpeg(2000);
    const bobFile2 = makeSamplePng(3000);
    const aliceFile1 = makeSampleJpeg(2500);

    // Initial offer: Bob sends 2 files with blurhash
    bob.prepareAndSendBatchOffer([
      { cleanBytes: bobFile1, mime: 'image/jpeg', previewMode: 'blurhash', blurhash: 'L6PZfSi_.AyE_3t7t7R**0o#DgR4', declaredMax: 5000 },
      { cleanBytes: bobFile2, mime: 'image/png', previewMode: 'blurhash', blurhash: 'L5H2EC=~p0W=~qj[f6j[00ayoffQ', declaredMax: 5000 }
    ]);

    alice.prepareAndSendBatchOffer([
      { cleanBytes: aliceFile1, mime: 'image/jpeg', previewMode: 'blurhash', blurhash: 'L6PZfSi_.AyE_3t7t7R**0o#DgR4', declaredMax: 5000 }
    ]);

    expect(bob.getState()).toBe('both_offered');
    expect(alice.getState()).toBe('both_offered');

    // Alice accepts first
    alice.acceptExchange();
    expect(alice.getState()).toBe('accepted_locally');

    // Bob now toggles file 2 from blurhash to thumbnail!
    bob.prepareAndSendBatchOffer([
      { cleanBytes: bobFile1, mime: 'image/jpeg', previewMode: 'blurhash', blurhash: 'L6PZfSi_.AyE_3t7t7R**0o#DgR4', declaredMax: 5000 },
      { cleanBytes: bobFile2, mime: 'image/png', previewMode: 'thumbnail', thumbnailDataUrl: 'data:image/jpeg;base64,samplethumb', declaredMax: 5000 }
    ]);

    // Alice should have received OFFER_RESET (notified with []), and then the updated offer with thumbnail
    expect(aliceOffersReceived.length).toBeGreaterThanOrEqual(3);
    const latestAliceOffer = aliceOffersReceived[aliceOffersReceived.length - 1];
    expect(latestAliceOffer.length).toBe(2);
    expect(latestAliceOffer[1].previewMode).toBe('thumbnail');
    expect(latestAliceOffer[1].thumbnailDataUrl).toBe('data:image/jpeg;base64,samplethumb');

    // Alice's prior consent MUST have been invalidated by the offer update
    expect(alice.getState()).toBe('both_offered');

    // Both now explicitly accept the updated offer
    bob.acceptExchange();
    alice.acceptExchange();

    await new Promise((r) => setTimeout(r, 60));

    expect(bobCompletedFiles.length).toBe(1);
    expect(aliceCompletedFiles.length).toBe(2);
    expect(bob.getState()).toBe('completed');
    expect(alice.getState()).toBe('completed');
  });

  it('11. clearLocalOffer: resets batch and notifies remote peer with OFFER_RESET', () => {
    const { bobSession, aliceSession } = createPairedNoiseSessions();
    let aliceOffersReceived: any[] = [];

    let alice: TransferProtocol;
    const bob = new TransferProtocol({
      isInitiator: true,
      noiseSession: bobSession,
      sendRawData: (data) => alice.handleIncomingMessage(data)
    });

    alice = new TransferProtocol({
      isInitiator: false,
      noiseSession: aliceSession,
      sendRawData: (data) => bob.handleIncomingMessage(data),
      onBatchOfferReceived: (items) => {
        aliceOffersReceived.push(items);
      }
    });

    bob.prepareAndSendBatchOffer([
      { cleanBytes: makeSampleJpeg(1000), mime: 'image/jpeg', previewMode: 'blurhash', declaredMax: 2000 }
    ]);

    expect((alice as any).remoteOfferItems.length).toBe(1);

    // Bob clears offer
    bob.clearLocalOffer();

    expect((bob as any).localBatch.length).toBe(0);
    expect((alice as any).remoteOfferItems.length).toBe(0);
    expect(aliceOffersReceived[aliceOffersReceived.length - 1]).toEqual([]);
  });
});
