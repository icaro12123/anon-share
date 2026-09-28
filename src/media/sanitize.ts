import { encode as encodeBlurhash } from 'blurhash';
import {
  SupportedMediaType,
  detectAndValidateMagicBytes,
  validateImageHeaderResolution,
  getDeclaredMaxSize
} from './magic.ts';

export type PreviewMode = 'blurhash' | 'thumbnail';
export const MAX_THUMBNAIL_BYTES = 8192; // 8 KB max

export interface ThumbnailResult {
  success: boolean;
  dataUrl?: string;
  fallbackToBlurhash?: boolean;
}

export interface SanitizedMedia {
  id?: string;
  cleanBytes: Uint8Array;
  mime: SupportedMediaType;
  extension: string;
  previewMode: PreviewMode;
  blurhash?: string;
  thumbnailDataUrl?: string;
  declaredMax: number;
  width?: number;
  height?: number;
  originalName?: string;
  thumbnailFallbackNotice?: boolean;
}

export function renderThumbnailDataUrl(
  sourceCanvas: HTMLCanvasElement | OffscreenCanvas,
  maxWidth = 120,
  maxHeight = 90,
  quality = 0.60
): string {
  let w = sourceCanvas.width;
  let h = sourceCanvas.height;
  if (w > maxWidth || h > maxHeight) {
    const ratio = Math.min(maxWidth / w, maxHeight / h);
    w = Math.max(1, Math.round(w * ratio));
    h = Math.max(1, Math.round(h * ratio));
  }

  if (typeof document !== 'undefined') {
    const thumbCanvas = document.createElement('canvas');
    thumbCanvas.width = w;
    thumbCanvas.height = h;
    const ctx = thumbCanvas.getContext('2d');
    if (!ctx) {
      throw new Error('Canvas 2D context unavailable');
    }
    ctx.drawImage(sourceCanvas as any, 0, 0, w, h);
    return thumbCanvas.toDataURL('image/jpeg', quality);
  }

  if (typeof (sourceCanvas as any).toDataURL === 'function') {
    return (sourceCanvas as any).toDataURL('image/jpeg', quality);
  }

  throw new Error('Ambiente senza supporto Canvas toDataURL');
}

/**
 * Generates a sanitized JPEG micro-thumbnail (<= 8 KB, max 120x90).
 * If size exceeds 8 KB after second pass (quality 0.45), falls back to blurhash.
 */
export function generateSanitizedThumbnail(
  sourceCanvas: HTMLCanvasElement | OffscreenCanvas,
  maxWidth = 120,
  maxHeight = 90
): ThumbnailResult {
  try {
    // 1st pass: 0.60 quality
    let dataUrl = renderThumbnailDataUrl(sourceCanvas, maxWidth, maxHeight, 0.60);
    let byteLen = new TextEncoder().encode(dataUrl).length;

    // 2nd pass: 0.45 quality if still > 8192 bytes
    if (byteLen > MAX_THUMBNAIL_BYTES) {
      dataUrl = renderThumbnailDataUrl(sourceCanvas, maxWidth, maxHeight, 0.45);
      byteLen = new TextEncoder().encode(dataUrl).length;
    }

    if (byteLen > MAX_THUMBNAIL_BYTES || !dataUrl.startsWith('data:image/jpeg;base64,')) {
      return { success: false, fallbackToBlurhash: true };
    }

    return { success: true, dataUrl };
  } catch {
    return { success: false, fallbackToBlurhash: true };
  }
}

/**
 * Extracts a frame from video at 0.5s on clean canvas and produces a sanitized thumbnail.
 */
export async function extractVideoThumbnail(
  cleanBytes: Uint8Array,
  mime: SupportedMediaType
): Promise<ThumbnailResult> {
  if (typeof document === 'undefined') {
    return { success: false, fallbackToBlurhash: true };
  }

  const blob = new Blob([cleanBytes as BlobPart], { type: mime });
  const objectUrl = URL.createObjectURL(blob);

  return new Promise<ThumbnailResult>((resolve) => {
    const video = document.createElement('video');
    video.preload = 'metadata';
    video.muted = true;
    video.playsInline = true;
    video.src = objectUrl;

    let resolved = false;
    const cleanup = () => {
      URL.revokeObjectURL(objectUrl);
      video.removeAttribute('src');
      video.load();
    };

    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        cleanup();
        resolve({ success: false, fallbackToBlurhash: true });
      }
    }, 2500);

    video.onloadeddata = () => {
      video.currentTime = Math.min(0.5, (video.duration || 1) / 2);
    };

    video.onseeked = () => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timeout);
      try {
        const w = video.videoWidth || 120;
        const h = video.videoHeight || 90;
        const canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          cleanup();
          resolve({ success: false, fallbackToBlurhash: true });
          return;
        }
        ctx.drawImage(video, 0, 0, w, h);
        const res = generateSanitizedThumbnail(canvas);
        cleanup();
        resolve(res);
      } catch {
        cleanup();
        resolve({ success: false, fallbackToBlurhash: true });
      }
    };

    video.onerror = () => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        cleanup();
        resolve({ success: false, fallbackToBlurhash: true });
      }
    };
  });
}

/**
 * Sanitizes an image file using Canvas re-encoding per Section 7:
 * - Eliminates EXIF, GPS, IPTC, XMP, and comments
 * - Computes BlurHash (4x3 components)
 * - Optionally generates micro-thumbnail if previewMode === 'thumbnail'
 * - Returns clean bytes and metadata
 */
export async function sanitizeImage(
  rawBytes: Uint8Array,
  mime: SupportedMediaType,
  _extension: string,
  previewMode: PreviewMode = 'blurhash'
): Promise<SanitizedMedia> {
  // 1. Anti-bomb header inspection before rendering
  const { width, height } = validateImageHeaderResolution(rawBytes, mime);

  // 2. Load into Image element
  const blob = new Blob([rawBytes as BlobPart], { type: mime });
  const objectUrl = URL.createObjectURL(blob);

  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error('Impossibile decodificare immagine'));
      el.src = objectUrl;
    });

    const w = img.naturalWidth || width || 100;
    const h = img.naturalHeight || height || 100;

    // 3. Draw on offscreen canvas
    let canvas: HTMLCanvasElement | OffscreenCanvas;
    let ctx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null = null;

    if (typeof OffscreenCanvas !== 'undefined') {
      canvas = new OffscreenCanvas(w, h);
      ctx = canvas.getContext('2d');
    } else {
      canvas = document.createElement('canvas');
      canvas.width = w;
      canvas.height = h;
      ctx = canvas.getContext('2d');
    }

    if (!ctx) {
      throw new Error('Contesto Canvas non disponibile');
    }

    ctx.drawImage(img, 0, 0, w, h);

    // 4. Calculate BlurHash on downscaled canvas (e.g. max 100px wide for speed)
    let blurhashStr: string | undefined;
    try {
      const bhWidth = Math.min(64, w);
      const bhHeight = Math.min(64, h);
      let bhCanvas: HTMLCanvasElement | OffscreenCanvas;
      let bhCtx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null = null;
      if (typeof OffscreenCanvas !== 'undefined') {
        bhCanvas = new OffscreenCanvas(bhWidth, bhHeight);
        bhCtx = bhCanvas.getContext('2d');
      } else {
        bhCanvas = document.createElement('canvas');
        bhCanvas.width = bhWidth;
        bhCanvas.height = bhHeight;
        bhCtx = bhCanvas.getContext('2d');
      }
      if (bhCtx) {
        bhCtx.drawImage(img, 0, 0, bhWidth, bhHeight);
        const imgData = bhCtx.getImageData(0, 0, bhWidth, bhHeight);
        blurhashStr = encodeBlurhash(imgData.data, bhWidth, bhHeight, 4, 3);
      }
    } catch {
      // Best effort blurhash
    }

    // 5. Optional micro-thumbnail generation
    let thumbnailDataUrl: string | undefined;
    let finalPreviewMode: PreviewMode = previewMode;
    let fallbackNotice = false;

    if (previewMode === 'thumbnail') {
      const thumbResult = generateSanitizedThumbnail(canvas);
      if (thumbResult.success && thumbResult.dataUrl) {
        thumbnailDataUrl = thumbResult.dataUrl;
      } else {
        finalPreviewMode = 'blurhash';
        fallbackNotice = true;
      }
    }

    // 6. Re-encode to clean blob (JPEG 95% or PNG or WebP)
    let cleanBlob: Blob;
    const exportType = mime === 'image/png' ? 'image/png' : 'image/jpeg';
    const quality = 0.95;

    if (canvas instanceof OffscreenCanvas) {
      cleanBlob = await canvas.convertToBlob({ type: exportType, quality });
    } else {
      cleanBlob = await new Promise<Blob>((resolve, reject) => {
        (canvas as HTMLCanvasElement).toBlob(
          (b) => (b ? resolve(b) : reject(new Error('Errore toBlob Canvas'))),
          exportType,
          quality
        );
      });
    }

    const cleanBuffer = await cleanBlob.arrayBuffer();
    const cleanBytes = new Uint8Array(cleanBuffer);

    return {
      cleanBytes,
      mime: exportType as SupportedMediaType,
      extension: exportType === 'image/png' ? 'png' : 'jpg',
      previewMode: finalPreviewMode,
      blurhash: blurhashStr,
      thumbnailDataUrl,
      declaredMax: getDeclaredMaxSize(cleanBytes.length),
      width: w,
      height: h,
      thumbnailFallbackNotice: fallbackNotice
    };
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

/**
 * Strips ID3v2 and ID3v1 tags from MP3 audio files.
 */
export function sanitizeMp3(bytes: Uint8Array): Uint8Array {
  let data = bytes;

  // 1. Strip ID3v2 at the beginning
  if (data.length >= 10 && data[0] === 0x49 && data[1] === 0x44 && data[2] === 0x33) {
    // Tag size is 4 synchsafe bytes (7 bits each) at offset 6..9
    const size = (data[6] << 21) | (data[7] << 14) | (data[8] << 7) | data[9];
    const totalHeader = 10 + size;
    if (totalHeader < data.length) {
      data = data.slice(totalHeader);
    }
  }

  // 2. Strip ID3v1 at the end (128 bytes starting with "TAG")
  if (data.length > 128) {
    const end = data.length - 128;
    if (data[end] === 0x54 && data[end + 1] === 0x41 && data[end + 2] === 0x47) {
      data = data.slice(0, end);
    }
  }

  return data;
}

/**
 * Strips Vorbis comment metadata block and Picture metadata block from FLAC audio.
 */
export function sanitizeFlac(bytes: Uint8Array): Uint8Array {
  if (bytes.length < 8) return bytes;
  // Verify 'fLaC' header
  if (bytes[0] !== 0x66 || bytes[1] !== 0x4c || bytes[2] !== 0x61 || bytes[3] !== 0x43) {
    return bytes;
  }

  const chunks: Uint8Array[] = [bytes.slice(0, 4)];
  let offset = 4;
  let isLast = false;

  while (offset + 4 <= bytes.length && !isLast) {
    const headerByte = bytes[offset];
    isLast = (headerByte & 0x80) !== 0;
    const blockType = headerByte & 0x7f;
    const length = (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];

    const blockTotalLen = 4 + length;
    if (offset + blockTotalLen > bytes.length) {
      break;
    }

    // Skip block type 4 (VORBIS_COMMENT) and type 6 (PICTURE)
    if (blockType === 4 || blockType === 6) {
      if (isLast) {
        // Fix previous chunk's isLast bit if this was the last metadata block
        if (chunks.length > 1) {
          const lastChunk = chunks[chunks.length - 1];
          lastChunk[0] |= 0x80;
        }
      }
    } else {
      chunks.push(bytes.slice(offset, offset + blockTotalLen));
    }

    offset += blockTotalLen;
  }

  // Append remaining audio frames
  if (offset < bytes.length) {
    chunks.push(bytes.slice(offset));
  }

  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

/**
 * Sanitizes MP4 moov container per Section 7:
 * - Strips user metadata boxes `udta` and `meta`
 * - Sets creation_time and modification_time to 0 in `mvhd`, `tkhd`, `mdhd`
 */
export function sanitizeMp4(bytes: Uint8Array): Uint8Array {
  function processBoxes(data: Uint8Array): Uint8Array {
    const output: Uint8Array[] = [];
    let offset = 0;

    while (offset + 8 <= data.length) {
      const view = new DataView(data.buffer, data.byteOffset + offset, data.byteLength - offset);
      let size = view.getUint32(0, false);
      const type = String.fromCharCode(
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7]
      );
      let headerLen = 8;

      if (size === 1) {
        if (offset + 16 > data.length) break;
        size = Number(view.getBigUint64(8, false));
        headerLen = 16;
      } else if (size === 0) {
        size = data.length - offset;
      }

      if (size < headerLen || offset + size > data.length) {
        output.push(data.slice(offset));
        break;
      }

      // Strip udta and meta boxes per Section 7
      if (type === 'udta' || type === 'meta') {
        offset += size;
        continue;
      }

      const boxBody = data.slice(offset + headerLen, offset + size);

      if (type === 'moov' || type === 'trak' || type === 'mdia' || type === 'minf') {
        const cleanChildren = processBoxes(boxBody);
        const newSize = headerLen + cleanChildren.length;
        const newBox = new Uint8Array(newSize);
        const newView = new DataView(newBox.buffer);
        newView.setUint32(0, newSize, false);
        newBox.set(data.slice(offset + 4, offset + headerLen), 4);
        newBox.set(cleanChildren, headerLen);
        output.push(newBox);
      } else if (type === 'mvhd' || type === 'tkhd' || type === 'mdhd') {
        // Zero timestamps
        const cleanBox = new Uint8Array(data.slice(offset, offset + size));
        const version = cleanBox[headerLen];
        if (version === 0) {
          // creation_time at headerLen + 4, modification_time at headerLen + 8 (4 bytes each)
          cleanBox.fill(0, headerLen + 4, headerLen + 12);
        } else if (version === 1) {
          // 8 bytes each
          cleanBox.fill(0, headerLen + 4, headerLen + 20);
        }
        output.push(cleanBox);
      } else {
        output.push(data.slice(offset, offset + size));
      }

      offset += size;
    }

    const totalLen = output.reduce((acc, b) => acc + b.length, 0);
    const result = new Uint8Array(totalLen);
    let pos = 0;
    for (const b of output) {
      result.set(b, pos);
      pos += b.length;
    }
    return result;
  }

  return processBoxes(bytes);
}

/**
 * Main sanitization dispatcher for selected user media file.
 */
export async function sanitizeMediaFile(
  file: File,
  previewMode: PreviewMode = 'blurhash'
): Promise<SanitizedMedia> {
  const buffer = await file.arrayBuffer();
  const rawBytes = new Uint8Array(buffer);

  // Validate magic bytes
  const detected = detectAndValidateMagicBytes(rawBytes);

  if (detected.isImage) {
    const res = await sanitizeImage(rawBytes, detected.mime, detected.extension, previewMode);
    return {
      ...res,
      id: crypto.randomUUID(),
      originalName: file.name
    };
  }

  let cleanBytes: Uint8Array = rawBytes;
  if (detected.mime === 'audio/mpeg') {
    cleanBytes = sanitizeMp3(rawBytes) as any;
  } else if (detected.mime === 'audio/flac') {
    cleanBytes = sanitizeFlac(rawBytes) as any;
  } else if (detected.mime === 'video/mp4') {
    cleanBytes = sanitizeMp4(rawBytes) as any;
  }

  let thumbnailDataUrl: string | undefined;
  let finalPreviewMode: PreviewMode = previewMode;
  let fallbackNotice = false;

  if (detected.isVideo && previewMode === 'thumbnail') {
    const thumbRes = await extractVideoThumbnail(cleanBytes, detected.mime);
    if (thumbRes.success && thumbRes.dataUrl) {
      thumbnailDataUrl = thumbRes.dataUrl;
    } else {
      finalPreviewMode = 'blurhash';
      fallbackNotice = true;
    }
  }

  return {
    id: crypto.randomUUID(),
    cleanBytes,
    mime: detected.mime,
    extension: detected.extension,
    previewMode: finalPreviewMode,
    thumbnailDataUrl,
    declaredMax: getDeclaredMaxSize(cleanBytes.length),
    originalName: file.name,
    thumbnailFallbackNotice: fallbackNotice
  };
}
