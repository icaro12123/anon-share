export type SupportedMediaType =
  | 'image/jpeg'
  | 'image/png'
  | 'image/webp'
  | 'video/mp4'
  | 'video/webm'
  | 'audio/mpeg'
  | 'audio/flac';

export interface MediaDetectionResult {
  mime: SupportedMediaType;
  extension: string;
  isImage: boolean;
  isVideo: boolean;
  isAudio: boolean;
}

export const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB hard limit
export const MAX_PIXEL_DIMENSION = 8192; // 8192 x 8192 max resolution
export const MAX_TOTAL_PIXELS = 40_000_000; // ~40 megapixels

/**
 * Size classes (upper bounds) for declared_max per Section 8:
 * [1MB, 5MB, 10MB, 25MB, 50MB, 100MB]
 */
export const SIZE_TIERS_BYTES = [
  1 * 1024 * 1024,
  5 * 1024 * 1024,
  10 * 1024 * 1024,
  25 * 1024 * 1024,
  50 * 1024 * 1024,
  100 * 1024 * 1024
];

export function getDeclaredMaxSize(actualBytes: number): number {
  if (actualBytes > MAX_FILE_SIZE_BYTES) {
    throw new Error(`Dimensione file (${actualBytes} byte) supera il limite consentito di 100 MB`);
  }
  for (const tier of SIZE_TIERS_BYTES) {
    if (actualBytes <= tier) {
      return tier;
    }
  }
  return MAX_FILE_SIZE_BYTES;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Validates magic bytes against Section 8 rigid allowlist.
 */
export function detectAndValidateMagicBytes(bytes: Uint8Array): MediaDetectionResult {
  if (bytes.length < 12) {
    throw new Error('File troppo piccolo o intestazione incompleta');
  }

  // Check HEIC/HEIF rejection
  if (isHeic(bytes)) {
    throw new Error('Formato HEIC non supportato: convertilo prima in JPEG o PNG.');
  }

  // JPEG: FF D8 FF
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return { mime: 'image/jpeg', extension: 'jpg', isImage: true, isVideo: false, isAudio: false };
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return { mime: 'image/png', extension: 'png', isImage: true, isVideo: false, isAudio: false };
  }

  // WebP: 52 49 46 46 (RIFF) ... 57 45 42 50 (WEBP)
  if (
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return { mime: 'image/webp', extension: 'webp', isImage: true, isVideo: false, isAudio: false };
  }

  // MP4: 00 00 00 ... 66 74 79 70 ("ftyp")
  if (
    bytes[4] === 0x66 &&
    bytes[5] === 0x74 &&
    bytes[6] === 0x79 &&
    bytes[7] === 0x70
  ) {
    return { mime: 'video/mp4', extension: 'mp4', isImage: false, isVideo: true, isAudio: false };
  }

  // WebM: 1A 45 DF A3 (EBML Header)
  if (
    bytes[0] === 0x1a &&
    bytes[1] === 0x45 &&
    bytes[2] === 0xdf &&
    bytes[3] === 0xa3
  ) {
    return { mime: 'video/webm', extension: 'webm', isImage: false, isVideo: true, isAudio: false };
  }

  // MP3: 49 44 33 ("ID3")
  if (bytes[0] === 0x49 && bytes[1] === 0x44 && bytes[2] === 0x33) {
    return { mime: 'audio/mpeg', extension: 'mp3', isImage: false, isVideo: false, isAudio: true };
  }

  // MP3 MPEG Audio sync frame: FF FB, FF F3, FF F2
  if (
    bytes[0] === 0xff &&
    (bytes[1] === 0xfb || bytes[1] === 0xf3 || bytes[1] === 0xf2)
  ) {
    return { mime: 'audio/mpeg', extension: 'mp3', isImage: false, isVideo: false, isAudio: true };
  }

  // FLAC: 66 4C 61 43 ("fLaC")
  if (
    bytes[0] === 0x66 &&
    bytes[1] === 0x4c &&
    bytes[2] === 0x61 &&
    bytes[3] === 0x43
  ) {
    return { mime: 'audio/flac', extension: 'flac', isImage: false, isVideo: false, isAudio: true };
  }

  throw new Error('Formato non supportato o signature magic bytes non valida.');
}

function isHeic(bytes: Uint8Array): boolean {
  if (bytes.length < 12) return false;
  // ftyp box containing heic, mif1, msf1
  if (bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
    if (brand === 'heic' || brand === 'mif1' || brand === 'msf1' || brand === 'heix') {
      return true;
    }
  }
  return false;
}

/**
 * Inspects header bytes of JPEG, PNG, and WebP before DOM rendering
 * to extract width & height, enforcing the Section 8 anti-decompression bomb limit.
 */
export function validateImageHeaderResolution(bytes: Uint8Array, mime: string): { width: number; height: number } {
  let width = 0;
  let height = 0;

  if (mime === 'image/png') {
    // PNG IHDR chunk starts at byte 12 (4 bytes chunk length, 4 bytes chunk type "IHDR", 4 bytes width, 4 bytes height)
    if (bytes.length < 24) throw new Error('Intestazione PNG incompleta');
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    width = view.getUint32(16, false);
    height = view.getUint32(20, false);
  } else if (mime === 'image/jpeg') {
    let offset = 2;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    while (offset < bytes.length - 8) {
      if (bytes[offset] !== 0xff) {
        offset++;
        continue;
      }
      const marker = bytes[offset + 1];
      // SOF markers (Start Of Frame): 0xC0 (baseline), 0xC1 (extended), 0xC2 (progressive)
      if (marker === 0xc0 || marker === 0xc1 || marker === 0xc2) {
        height = view.getUint16(offset + 5, false);
        width = view.getUint16(offset + 7, false);
        break;
      }
      const len = view.getUint16(offset + 2, false);
      offset += 2 + len;
    }
  } else if (mime === 'image/webp') {
    // WebP VP8 or VP8L or VP8X
    if (bytes.length > 30) {
      const format = String.fromCharCode(bytes[12], bytes[13], bytes[14], bytes[15]);
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (format === 'VP8 ') {
        // Lossy VP8: bytes 26-27 width, 28-29 height (little endian, 14-bit)
        width = (view.getUint16(26, true) & 0x3fff);
        height = (view.getUint16(28, true) & 0x3fff);
      } else if (format === 'VP8L') {
        // Lossless VP8L: signature 0x2f at byte 20, 28 bits width & height
        const b1 = bytes[21];
        const b2 = bytes[22];
        const b3 = bytes[23];
        const b4 = bytes[24];
        width = 1 + (((b2 & 0x3f) << 8) | b1);
        height = 1 + (((b4 & 0x0f) << 10) | (b3 << 2) | ((b2 & 0xc0) >> 6));
      } else if (format === 'VP8X') {
        // Extended VP8X: canvas width at 24-26 (24-bit little endian), height at 27-29
        width = 1 + (bytes[24] | (bytes[25] << 8) | (bytes[26] << 16));
        height = 1 + (bytes[27] | (bytes[28] << 8) | (bytes[29] << 16));
      }
    }
  }

  if (width > 0 && height > 0) {
    if (width > MAX_PIXEL_DIMENSION || height > MAX_PIXEL_DIMENSION) {
      throw new Error(
        `Risoluzione immagine (${width}x${height}) supera il limite massimo consentito di ${MAX_PIXEL_DIMENSION}x${MAX_PIXEL_DIMENSION}.`
      );
    }
    if (width * height > MAX_TOTAL_PIXELS) {
      throw new Error(
        `Area immagine (${width * height} pixel) supera il limite anti-bomb (~40 MP).`
      );
    }
  }

  return { width, height };
}

/**
 * Generates neutral local file name per Section 8: anon_YYYYMMDD_xxxx.ext
 */
export function generateNeutralFileName(extension: string): string {
  const d = new Date();
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');

  const randBytes = new Uint8Array(2);
  crypto.getRandomValues(randBytes);
  const randHex = (randBytes[0] * 256 + randBytes[1]).toString(16).padStart(4, '0');

  return `anon_${year}${month}${day}_${randHex}.${extension}`;
}
