import { describe, it, expect } from 'vitest';
import {
  detectAndValidateMagicBytes,
  validateImageHeaderResolution,
  generateNeutralFileName,
  getDeclaredMaxSize
} from '../media/magic.ts';
import {
  sanitizeMp3,
  sanitizeFlac,
  sanitizeMp4
} from '../media/sanitize.ts';

describe('Media Security, Magic Bytes & Container Sanitization (Sections 7 & 8)', () => {
  it('detects and validates all 7 supported media formats by magic bytes', () => {
    // JPEG
    const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 16, 0x4a, 0x46, 0x49, 0x46, 0, 0]);
    expect(detectAndValidateMagicBytes(jpeg).mime).toBe('image/jpeg');

    // PNG
    const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
    expect(detectAndValidateMagicBytes(png).mime).toBe('image/png');

    // WebP
    const webp = new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]);
    expect(detectAndValidateMagicBytes(webp).mime).toBe('image/webp');

    // MP4
    const mp4 = new Uint8Array([0, 0, 0, 20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d]);
    expect(detectAndValidateMagicBytes(mp4).mime).toBe('video/mp4');

    // WebM
    const webm = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 1, 2, 3, 4]);
    expect(detectAndValidateMagicBytes(webm).mime).toBe('video/webm');

    // MP3 (ID3)
    const mp3Id3 = new Uint8Array([0x49, 0x44, 0x33, 3, 0, 0, 0, 0, 0, 10, 0, 0]);
    expect(detectAndValidateMagicBytes(mp3Id3).mime).toBe('audio/mpeg');

    // MP3 (Sync Frame)
    const mp3Sync = new Uint8Array([0xff, 0xfb, 0x90, 0x44, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(detectAndValidateMagicBytes(mp3Sync).mime).toBe('audio/mpeg');

    // FLAC
    const flac = new Uint8Array([0x66, 0x4c, 0x61, 0x43, 0, 0, 0, 34, 0, 0, 0, 0]);
    expect(detectAndValidateMagicBytes(flac).mime).toBe('audio/flac');
  });

  it('strictly rejects HEIC files with informative notice', () => {
    const heic = new Uint8Array([0, 0, 0, 24, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63]);
    expect(() => detectAndValidateMagicBytes(heic)).toThrow(/HEIC non supportato/);
  });

  it('rejects unsupported or malicious formats (PDF, EXE, etc.)', () => {
    // PDF: %PDF
    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0, 0, 0, 0]);
    expect(() => detectAndValidateMagicBytes(pdf)).toThrow();

    // EXE: MZ
    const exe = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0, 0, 0, 0]);
    expect(() => detectAndValidateMagicBytes(exe)).toThrow();
  });

  it('enforces pre-decode image resolution limit of 8192x8192 (anti-decompression bomb)', () => {
    // Construct mock PNG IHDR header
    const pngHeader = new Uint8Array(32);
    pngHeader.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
    const view = new DataView(pngHeader.buffer);

    // 1. Valid resolution (1920x1080)
    view.setUint32(16, 1920, false);
    view.setUint32(20, 1080, false);
    const valid = validateImageHeaderResolution(pngHeader, 'image/png');
    expect(valid.width).toBe(1920);
    expect(valid.height).toBe(1080);

    // 2. Bomb resolution (10000x10000 > 8192x8192)
    view.setUint32(16, 10000, false);
    view.setUint32(20, 10000, false);
    expect(() => validateImageHeaderResolution(pngHeader, 'image/png')).toThrow(/limite massimo consentito/);
  });

  it('strips ID3v2 metadata header from MP3 files', () => {
    // MP3 with 10-byte ID3 header + 4 bytes content, followed by audio sync frame FF FB
    const rawMp3 = new Uint8Array([
      0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
      0xaa, 0xbb, 0xcc, 0xdd, // ID3 body
      0xff, 0xfb, 0x90, 0x44  // Audio frame
    ]);

    const clean = sanitizeMp3(rawMp3);
    expect(clean.length).toBe(4);
    expect(clean[0]).toBe(0xff);
    expect(clean[1]).toBe(0xfb);
  });

  it('strips Vorbis comment metadata block from FLAC', () => {
    // FLAC header "fLaC" + Block type 4 (Vorbis Comment, length 4) + Audio frame
    const rawFlac = new Uint8Array([
      0x66, 0x4c, 0x61, 0x43, // fLaC
      0x04, 0x00, 0x00, 0x04, // Block type 4, length 4
      0x01, 0x02, 0x03, 0x04, // Vorbis comment body
      0xff, 0xf8, 0x00, 0x00  // Audio data
    ]);

    const clean = sanitizeFlac(rawFlac);
    expect(clean.length).toBe(8); // "fLaC" (4) + Audio data (4)
    expect(clean[0]).toBe(0x66);
    expect(clean[4]).toBe(0xff);
  });

  it('sanitizes MP4 container: strips udta & meta boxes, and zeroes mvhd creation/modification timestamps', () => {
    const ftyp = new Uint8Array([0, 0, 0, 16, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d, 0, 0, 0, 0]);
    
    // mvhd atom with non-zero timestamps at offset 4..11
    const mvhd = new Uint8Array([
      0, 0, 0, 24,
      0x6d, 0x76, 0x68, 0x64, // 'mvhd'
      0, 0, 0, 0,             // version 0, flags
      0x11, 0x22, 0x33, 0x44, // creation_time
      0x55, 0x66, 0x77, 0x88, // modification_time
      0, 0, 0, 0
    ]);

    // udta atom
    const udta = new Uint8Array([0, 0, 0, 12, 0x75, 0x64, 0x74, 0x61, 1, 2, 3, 4]);

    const moovLen = 8 + mvhd.length + udta.length;
    const moov = new Uint8Array(moovLen);
    new DataView(moov.buffer).setUint32(0, moovLen, false);
    moov.set([0x6d, 0x6f, 0x6f, 0x76], 4);
    moov.set(mvhd, 8);
    moov.set(udta, 8 + mvhd.length);

    const fullMp4 = new Uint8Array(ftyp.length + moov.length);
    fullMp4.set(ftyp, 0);
    fullMp4.set(moov, ftyp.length);

    const cleanMp4 = sanitizeMp4(fullMp4);

    // udta must be removed
    const hasUdta = cleanMp4.some(
      (b, i) => b === 0x75 && cleanMp4[i + 1] === 0x64 && cleanMp4[i + 2] === 0x74 && cleanMp4[i + 3] === 0x61
    );
    expect(hasUdta).toBe(false);

    // Timestamps inside mvhd must be 0
    const mvhdIndex = cleanMp4.findIndex(
      (b, i) => b === 0x6d && cleanMp4[i + 1] === 0x76 && cleanMp4[i + 2] === 0x68 && cleanMp4[i + 3] === 0x64
    );
    expect(mvhdIndex).toBeGreaterThan(0);
    // creation_time at mvhdIndex + 8, modification_time at mvhdIndex + 12
    expect(cleanMp4[mvhdIndex + 8]).toBe(0);
    expect(cleanMp4[mvhdIndex + 9]).toBe(0);
    expect(cleanMp4[mvhdIndex + 12]).toBe(0);
    expect(cleanMp4[mvhdIndex + 13]).toBe(0);
  });

  it('generates strictly neutral filenames per Section 8: anon_YYYYMMDD_xxxx.ext', () => {
    const filename = generateNeutralFileName('jpg');
    expect(filename).toMatch(/^anon_\d{8}_[0-9a-f]{4}\.jpg$/);
  });

  it('computes declared_max upper bounds correctly', () => {
    expect(getDeclaredMaxSize(500_000)).toBe(1 * 1024 * 1024);
    expect(getDeclaredMaxSize(3 * 1024 * 1024)).toBe(5 * 1024 * 1024);
    expect(getDeclaredMaxSize(80 * 1024 * 1024)).toBe(100 * 1024 * 1024);
    expect(() => getDeclaredMaxSize(105 * 1024 * 1024)).toThrow(/supera il limite/);
  });
});
