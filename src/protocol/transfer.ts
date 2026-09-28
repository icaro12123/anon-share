import { NoiseSession } from '../crypto/noise.ts';
import { toHex, fromHex, calculateFileCommitment } from '../crypto/keys.ts';
import {
  MAX_FILE_SIZE_BYTES,
  MAX_BATCH_FILES,
  MAX_BATCH_TOTAL_BYTES,
  SupportedMediaType,
  getSafeExtensionForMime,
  generateIndexedNeutralFileName,
  verifyMagicBytesForMime,
  isMimeSupported
} from '../media/magic.ts';
import { MAX_THUMBNAIL_BYTES, PreviewMode } from '../media/sanitize.ts';

export const CHUNK_SIZE = 16384; // 16 KiB per Section 6
export const MSG_TYPE_CONTROL = 0x01;
export const MSG_TYPE_DATA = 0x02;

export interface FileOffer {
  commitment: string; // hex
  previewMode?: PreviewMode;
  blurhash?: string;
  thumbnailDataUrl?: string;
  declaredMax: number;
  mime: SupportedMediaType;
  extension: string;
}

export interface OfferItemPayload {
  index: number;
  commitment: string;
  previewMode: PreviewMode;
  blurhash?: string;
  thumbnailDataUrl?: string;
  declaredMax: number;
  mime: SupportedMediaType;
}

export interface OfferEndPayload {
  count: number;
  totalDeclaredMax: number;
}

export interface BatchAcceptPayload {
  myCommitments: string[];
  peerCommitments: string[];
}

export interface BatchSaltsPayload {
  salts: string[]; // positional array: salts[i] = salt of file with index i
}

export interface FileStartPayload {
  fileIndex: number;
  totalBytes: number;
}

export interface FileEndPayload {
  fileIndex: number;
  totalBytes: number;
}

export interface BatchReceiveCompletePayload {
  confirmedItemCount: number;
}

export type TransferState =
  | 'idle'
  | 'files_selected'
  | 'offer_sent'
  | 'offer_received'
  | 'both_offered'
  | 'accepted_locally'
  | 'accepted_both'
  | 'streaming'
  | 'verifying'
  | 'waiting_peer_completion'
  | 'completed'
  | 'error';

export interface TransferProgress {
  bytesSent: number;
  totalToSend: number;
  bytesReceived: number;
  totalToReceive: number;
  currentSendingFileIndex?: number;
  currentReceivingFileIndex?: number;
}

export interface CompletedFile {
  name: string;
  blob: Blob;
  mime: string;
  size: number;
  data: Uint8Array;
}

export interface LocalBatchItem {
  cleanBytes: Uint8Array;
  mime: SupportedMediaType;
  previewMode: PreviewMode;
  blurhash?: string;
  thumbnailDataUrl?: string;
  declaredMax: number;
  salt?: Uint8Array;
  commitment?: Uint8Array;
  commitmentHex?: string;
}

export interface TransferProtocolOptions {
  isInitiator: boolean;
  noiseSession: NoiseSession;
  sendRawData: (data: Uint8Array) => void;
  onStateChange?: (state: TransferState, message?: string) => void;
  onOfferReceived?: (offer: FileOffer) => void;
  onBatchOfferReceived?: (items: OfferItemPayload[]) => void;
  onProgress?: (progress: TransferProgress) => void;
  onFileCompleted?: (file: CompletedFile) => void;
  onBatchCompleted?: (files: CompletedFile[]) => void;
  onError?: (error: string) => void;
}

/**
 * Implements Section 5 (The 3-stage exchange protocol) & Section 6 (Noise chunk streaming)
 * with Multi-Media Batch, Positional Indexing, Strict Receiver Byte/Magic Validation,
 * and Reciprocal Completion Gate.
 */
export class TransferProtocol {
  public readonly isInitiator: boolean;
  private readonly noiseSession: NoiseSession;
  private readonly sendRawData: (data: Uint8Array) => void;

  private state: TransferState = 'idle';
  private isAborted: boolean = false;

  // Local batch items
  private localBatch: LocalBatchItem[] = [];

  // Remote batch offer
  private remoteOfferItems: OfferItemPayload[] = [];
  private remoteOfferComplete: boolean = false;
  private remoteSalts: Uint8Array[] | null = null;

  // Receiver streaming state
  private activeReceiveFileIndex: number | null = null;
  private expectedNextFileIndex: number = 0;
  private currentFileReceivedBytes: number = 0;
  private currentFileTotalBytesExpected: number | null = null;
  private currentFileChunks: Uint8Array[] = [];
  private lockedReceivedFiles: CompletedFile[] = [];

  // Consent & gate flags
  private localAccepted: boolean = false;
  private remoteAccepted: boolean = false;
  private localSendDone: boolean = false;
  private localReceiveDone: boolean = false;
  private peerReceiveDone: boolean = false;

  // Callbacks
  private onStateChange?: (state: TransferState, message?: string) => void;
  private onOfferReceived?: (offer: FileOffer) => void;
  private onBatchOfferReceived?: (items: OfferItemPayload[]) => void;
  private onProgress?: (progress: TransferProgress) => void;
  private onFileCompleted?: (file: CompletedFile) => void;
  private onBatchCompleted?: (files: CompletedFile[]) => void;
  private onError?: (error: string) => void;

  private bytesSent: number = 0;
  private totalBytesToSend: number = 0;

  constructor(options: TransferProtocolOptions) {
    this.isInitiator = options.isInitiator;
    this.noiseSession = options.noiseSession;
    this.sendRawData = options.sendRawData;
    this.onStateChange = options.onStateChange;
    this.onOfferReceived = options.onOfferReceived;
    this.onBatchOfferReceived = options.onBatchOfferReceived;
    this.onProgress = options.onProgress;
    this.onFileCompleted = options.onFileCompleted;
    this.onBatchCompleted = options.onBatchCompleted;
    this.onError = options.onError;
  }

  private setState(state: TransferState, message?: string): void {
    if (this.state === 'error' && state !== 'error') return;
    this.state = state;
    this.onStateChange?.(state, message);
  }

  public getState(): TransferState {
    return this.state;
  }

  public getRemoteOffer(): FileOffer | null {
    if (this.remoteOfferItems.length === 0) return null;
    const first = this.remoteOfferItems[0];
    return {
      commitment: first.commitment,
      previewMode: first.previewMode,
      blurhash: first.blurhash,
      thumbnailDataUrl: first.thumbnailDataUrl,
      declaredMax: first.declaredMax,
      mime: first.mime,
      extension: getSafeExtensionForMime(first.mime)
    };
  }

  public getRemoteOfferItems(): OfferItemPayload[] {
    return this.remoteOfferItems;
  }

  /**
   * Stage 1: Prepares local batch, generates salts, computes commitments,
   * and sends sequential OFFER_ITEM messages followed by OFFER_END.
   */
  public prepareAndSendBatchOffer(items: LocalBatchItem[]): void {
    if (items.length === 0) {
      throw new Error('Impossibile inviare offerta batch vuota');
    }
    if (items.length > MAX_BATCH_FILES) {
      throw new Error(`Numero file (${items.length}) eccede il limite di ${MAX_BATCH_FILES}`);
    }

    const totalDeclared = items.reduce((acc, it) => acc + it.declaredMax, 0);
    if (totalDeclared > MAX_BATCH_TOTAL_BYTES) {
      throw new Error(`Dimensione totale dichiarata (${totalDeclared}) supera 100 MB`);
    }

    this.localBatch = [];
    this.totalBytesToSend = items.reduce((acc, it) => acc + it.cleanBytes.length, 0);
    this.bytesSent = 0;

    // 1. Process items and send OFFER_ITEM sequentially
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const salt = new Uint8Array(32);
      crypto.getRandomValues(salt);

      const commitment = calculateFileCommitment(salt, item.cleanBytes);
      const commitmentHex = toHex(commitment);

      const localItem: LocalBatchItem = {
        ...item,
        salt,
        commitment,
        commitmentHex
      };
      this.localBatch.push(localItem);

      const offerItemPayload: OfferItemPayload = {
        index: i,
        commitment: commitmentHex,
        previewMode: item.previewMode,
        blurhash: item.blurhash,
        thumbnailDataUrl: item.thumbnailDataUrl,
        declaredMax: item.declaredMax,
        mime: item.mime
      };

      this.sendControlMessage('OFFER_ITEM', offerItemPayload);
    }

    // 2. Send OFFER_END
    const offerEndPayload: OfferEndPayload = {
      count: items.length,
      totalDeclaredMax: totalDeclared
    };
    this.sendControlMessage('OFFER_END', offerEndPayload);

    if (this.remoteOfferComplete) {
      this.setState('both_offered', 'Offerte scambiate con successo. Verifica anteprime prima di accettare');
    } else {
      this.setState('offer_sent', 'Offerta inviata. In attesa del file della controparte...');
    }
  }

  /**
   * Compatibility wrapper for single-file offer.
   */
  public prepareAndSendOffer(options: {
    cleanBytes: Uint8Array;
    mime: SupportedMediaType;
    extension?: string;
    blurhash?: string;
    thumbnailDataUrl?: string;
    declaredMax: number;
    previewMode?: PreviewMode;
  }): void {
    this.prepareAndSendBatchOffer([
      {
        cleanBytes: options.cleanBytes,
        mime: options.mime,
        previewMode: options.previewMode ?? (options.thumbnailDataUrl ? 'thumbnail' : 'blurhash'),
        blurhash: options.blurhash,
        thumbnailDataUrl: options.thumbnailDataUrl,
        declaredMax: options.declaredMax
      }
    ]);
  }

  /**
   * Stage 2: User clicks "Accetta Scambio".
   */
  public acceptExchange(): void {
    if (this.localBatch.length === 0 || !this.remoteOfferComplete) {
      throw new Error('Impossibile accettare prima di aver completato lo scambio delle offerte');
    }
    this.localAccepted = true;

    // Send BATCH_ACCEPT { myCommitments, peerCommitments }
    const payload: BatchAcceptPayload = {
      myCommitments: this.localBatch.map((it) => it.commitmentHex!),
      peerCommitments: this.remoteOfferItems.map((it) => it.commitment)
    };
    this.sendControlMessage('BATCH_ACCEPT', payload);

    if (this.remoteAccepted) {
      this.startStage3Streaming();
    } else {
      this.setState('accepted_locally', 'Hai accettato lo scambio. In attesa del consenso del peer...');
    }
  }

  /**
   * Stage 3: Revelation of salts (positional array), streaming DATA chunks, and FILE_START / FILE_END per file.
   */
  private async startStage3Streaming(): Promise<void> {
    if (this.isAborted) return;
    this.setState('accepted_both', 'Doppio consenso verificato. Avvio trasferimento...');

    // 1. Send BATCH_SALTS { salts: [salt_0, salt_1, ...] }
    const salts = this.localBatch.map((it) => toHex(it.salt!));
    this.sendControlMessage('BATCH_SALTS', { salts });

    if (this.isAborted) return;
    this.setState('streaming', 'Trasferimento dati cifrati in corso...');

    // 2. Stream all files sequentially
    for (let fileIndex = 0; fileIndex < this.localBatch.length; fileIndex++) {
      if (this.isAborted) return;
      const file = this.localBatch[fileIndex];
      const totalBytes = file.cleanBytes.length;

      // Send FILE_START { fileIndex, totalBytes }
      this.sendControlMessage('FILE_START', { fileIndex, totalBytes });

      let offset = 0;
      while (offset < totalBytes) {
        if (this.isAborted) return;
        const end = Math.min(offset + CHUNK_SIZE, totalBytes);
        const chunk = file.cleanBytes.subarray(offset, end);

        // Framing: [MSG_TYPE_DATA (0x02), uint16 fileIndex, chunk_bytes...]
        const plaintext = new Uint8Array(3 + chunk.length);
        plaintext[0] = MSG_TYPE_DATA;
        plaintext[1] = (fileIndex >> 8) & 0xff;
        plaintext[2] = fileIndex & 0xff;
        plaintext.set(chunk, 3);

        const ciphertext = this.noiseSession.encrypt(plaintext);
        this.sendRawData(ciphertext);

        offset = end;
        this.bytesSent += chunk.length;
        this.emitProgress(fileIndex);

        // Yield event loop briefly every few chunks to prevent freezing UI
        if (offset % (CHUNK_SIZE * 8) === 0) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }

      if (this.isAborted) return;

      // Send FILE_END { fileIndex, totalBytes }
      this.sendControlMessage('FILE_END', { fileIndex, totalBytes });
    }

    this.localSendDone = true;
    this.checkReciprocalCompletion();
  }

  /**
   * Handles incoming raw message from WebRTC DataChannel.
   */
  public handleIncomingMessage(rawCiphertext: Uint8Array): void {
    if (this.isAborted) return;

    let plaintext: Uint8Array;
    try {
      plaintext = this.noiseSession.decrypt(rawCiphertext);
    } catch {
      this.handleError('Errore di decifratura Noise su pacchetto (possibile manomissione o desincronizzazione)');
      return;
    }

    if (plaintext.length < 1) return;

    const msgType = plaintext[0];
    if (msgType === MSG_TYPE_CONTROL) {
      this.handleControlMessage(plaintext.subarray(1));
    } else if (msgType === MSG_TYPE_DATA) {
      this.handleDataChunk(plaintext.subarray(1));
    }
  }

  private handleControlMessage(payloadBytes: Uint8Array): void {
    let data: any;
    try {
      const jsonStr = new TextDecoder().decode(payloadBytes);
      data = JSON.parse(jsonStr);
    } catch {
      return;
    }

    switch (data.type) {
      case 'OFFER_ITEM': {
        this.handleOfferItem(data.payload as OfferItemPayload);
        break;
      }

      case 'OFFER_END': {
        this.handleOfferEnd(data.payload as OfferEndPayload);
        break;
      }

      case 'BATCH_ACCEPT':
      case 'ACCEPT': {
        this.handleBatchAccept(data.payload);
        break;
      }

      case 'BATCH_SALTS':
      case 'SALT': {
        this.handleBatchSalts(data.payload);
        break;
      }

      case 'FILE_START': {
        this.handleFileStart(data.payload as FileStartPayload);
        break;
      }

      case 'FILE_END': {
        this.handleFileEnd(data.payload as FileEndPayload);
        break;
      }

      case 'BATCH_RECEIVE_COMPLETE': {
        this.handleBatchReceiveComplete(data.payload as BatchReceiveCompletePayload);
        break;
      }
    }
  }

  private handleOfferItem(item: OfferItemPayload): void {
    if (this.remoteOfferComplete) {
      this.handleError('Ricevuto OFFER_ITEM dopo che l offerta era gia stata conclusa');
      return;
    }

    // Index validation
    if (item.index !== this.remoteOfferItems.length) {
      this.handleError(`Indice OFFER_ITEM non sequenziale (atteso ${this.remoteOfferItems.length}, ricevuto ${item.index})`);
      return;
    }
    if (item.index >= MAX_BATCH_FILES) {
      this.handleError(`Superato limite massimo di ${MAX_BATCH_FILES} file nel batch`);
      return;
    }

    // MIME allowlist validation
    if (!isMimeSupported(item.mime)) {
      this.handleError(`MIME type non supportato o non in allowlist: ${item.mime}`);
      return;
    }

    // Commitment format validation (64 hex characters)
    if (!item.commitment || !/^[0-9a-fA-F]{64}$/.test(item.commitment)) {
      this.handleError('Commitment SHA-256 non valido nell offerta');
      return;
    }

    // DeclaredMax validation
    if (!item.declaredMax || item.declaredMax <= 0 || item.declaredMax > MAX_FILE_SIZE_BYTES) {
      this.handleError(`declaredMax non valido per item ${item.index}: ${item.declaredMax}`);
      return;
    }

    // Thumbnail validation if permissive preview
    if (item.previewMode === 'thumbnail') {
      if (!item.thumbnailDataUrl || typeof item.thumbnailDataUrl !== 'string') {
        this.handleError(`Miniatura mancante per item ${item.index} in modalita thumbnail`);
        return;
      }
      if (!item.thumbnailDataUrl.startsWith('data:image/jpeg;base64,')) {
        this.handleError('Formato miniatura non conforme: deve iniziare con data:image/jpeg;base64,');
        return;
      }
      const thumbBytesLen = new TextEncoder().encode(item.thumbnailDataUrl).length;
      if (thumbBytesLen > MAX_THUMBNAIL_BYTES) {
        this.handleError(`Dimensione miniatura (${thumbBytesLen} byte) supera il limite di 8 KB`);
        return;
      }
    }

    this.remoteOfferItems.push(item);
  }

  private handleOfferEnd(payload: OfferEndPayload): void {
    if (this.remoteOfferComplete) {
      this.handleError('OFFER_END duplicato');
      return;
    }

    // Validate count
    if (payload.count !== this.remoteOfferItems.length) {
      this.handleError(
        `Discrepanza count in OFFER_END: dichiarato ${payload.count}, ricevuti ${this.remoteOfferItems.length}`
      );
      return;
    }
    if (payload.count <= 0 || payload.count > MAX_BATCH_FILES) {
      this.handleError(`Conteggio file in OFFER_END non consentito: ${payload.count}`);
      return;
    }

    // Validate total declared max
    const sumDeclared = this.remoteOfferItems.reduce((acc, it) => acc + it.declaredMax, 0);
    if (sumDeclared !== payload.totalDeclaredMax) {
      this.handleError(
        `Discrepanza totalDeclaredMax: dichiarato ${payload.totalDeclaredMax}, calcolato ${sumDeclared}`
      );
      return;
    }
    if (sumDeclared > MAX_BATCH_TOTAL_BYTES) {
      this.handleError(`Dimensione cumulativa batch (${sumDeclared}) supera il tetto consentito di 100 MB`);
      return;
    }

    this.remoteOfferComplete = true;
    this.onBatchOfferReceived?.(this.remoteOfferItems);

    const firstOffer = this.getRemoteOffer();
    if (firstOffer) {
      this.onOfferReceived?.(firstOffer);
    }

    if (this.localBatch.length > 0) {
      this.setState('both_offered', 'Offerte scambiate con successo. Verifica anteprime prima di accettare');
    } else {
      this.setState('offer_received', 'Ricevuta offerta dal peer. Seleziona i tuoi file da scambiare');
    }
  }

  private handleBatchAccept(payload: any): void {
    const peerCommitments: string[] = payload.peerCommitments || (payload.peerCommitment ? [payload.peerCommitment] : []);
    const myCommitments: string[] = payload.myCommitments || (payload.myCommitment ? [payload.myCommitment] : []);

    const expectedLocalCommitments = this.localBatch.map((it) => it.commitmentHex!);
    const expectedRemoteCommitments = this.remoteOfferItems.map((it) => it.commitment);

    // Verify dual consent commitments match exactly
    if (
      peerCommitments.length !== expectedLocalCommitments.length ||
      myCommitments.length !== expectedRemoteCommitments.length
    ) {
      this.handleError('Discrepanza nel conteggio dei commitment nel messaggio di accettazione');
      return;
    }

    for (let i = 0; i < expectedLocalCommitments.length; i++) {
      if (peerCommitments[i].toLowerCase() !== expectedLocalCommitments[i].toLowerCase()) {
        this.handleError(`Discrepanza nel commitment locale ${i} accettato dal peer`);
        return;
      }
    }

    for (let i = 0; i < expectedRemoteCommitments.length; i++) {
      if (myCommitments[i].toLowerCase() !== expectedRemoteCommitments[i].toLowerCase()) {
        this.handleError(`Discrepanza nel commitment remoto ${i} inviato dal peer`);
        return;
      }
    }

    this.remoteAccepted = true;
    if (this.localAccepted) {
      this.startStage3Streaming();
    }
  }

  private handleBatchSalts(payload: any): void {
    let saltsList: string[] = [];
    if (Array.isArray(payload.salts)) {
      saltsList = payload.salts;
    } else if (payload.salt && typeof payload.salt === 'string') {
      saltsList = [payload.salt];
    } else {
      this.handleError('Formato BATCH_SALTS non valido');
      return;
    }

    if (saltsList.length !== this.remoteOfferItems.length) {
      this.handleError(
        `Discrepanza conteggio salts: ricevuti ${saltsList.length}, attesi ${this.remoteOfferItems.length}`
      );
      return;
    }

    try {
      this.remoteSalts = saltsList.map((s) => {
        const bytes = fromHex(s);
        if (bytes.length !== 32) {
          throw new Error('Lunghezza salt errata');
        }
        return bytes;
      });
    } catch {
      this.handleError('Salt remoto non decodificabile o lunghezza errata');
      return;
    }
  }

  private handleFileStart(payload: FileStartPayload): void {
    if (this.activeReceiveFileIndex !== null) {
      this.handleError('Ricevuto FILE_START prima che il file precedente fosse completato con FILE_END');
      return;
    }

    if (payload.fileIndex !== this.expectedNextFileIndex) {
      this.handleError(
        `FILE_START con fileIndex non sequenziale (atteso ${this.expectedNextFileIndex}, ricevuto ${payload.fileIndex})`
      );
      return;
    }

    if (payload.fileIndex >= this.remoteOfferItems.length) {
      this.handleError(`FILE_START con fileIndex (${payload.fileIndex}) fuori dal range dell offerta`);
      return;
    }

    const itemOffer = this.remoteOfferItems[payload.fileIndex];
    if (payload.totalBytes <= 0 || payload.totalBytes > itemOffer.declaredMax) {
      this.handleError(
        `Dimensione file in FILE_START (${payload.totalBytes}) supera declaredMax (${itemOffer.declaredMax})`
      );
      return;
    }

    this.activeReceiveFileIndex = payload.fileIndex;
    this.currentFileTotalBytesExpected = payload.totalBytes;
    this.currentFileReceivedBytes = 0;
    this.currentFileChunks = [];
  }

  private handleDataChunk(chunkWithIndex: Uint8Array): void {
    if (this.activeReceiveFileIndex === null) {
      this.handleError('Ricevuto chunk DATA senza un FILE_START attivo');
      return;
    }

    if (chunkWithIndex.length < 2) {
      this.handleError('Chunk DATA malformato (lunghezza insufficiente per fileIndex)');
      return;
    }

    const chunkFileIndex = (chunkWithIndex[0] << 8) | chunkWithIndex[1];
    const rawData = chunkWithIndex.subarray(2);

    if (chunkFileIndex !== this.activeReceiveFileIndex) {
      this.handleError(
        `Chunk DATA con fileIndex non valido o fuori sequenza (atteso ${this.activeReceiveFileIndex}, ricevuto ${chunkFileIndex})`
      );
      return;
    }

    this.currentFileReceivedBytes += rawData.length;
    const itemOffer = this.remoteOfferItems[this.activeReceiveFileIndex];

    // Cumulative byte ceiling check
    if (this.currentFileReceivedBytes > itemOffer.declaredMax) {
      this.handleError(
        `Byte cumulativi ricevuti per file ${this.activeReceiveFileIndex} (${this.currentFileReceivedBytes}) superano declaredMax (${itemOffer.declaredMax})`
      );
      return;
    }

    if (this.currentFileReceivedBytes > MAX_FILE_SIZE_BYTES) {
      this.handleError('Tetto massimo di 100 MB superato per singolo file');
      return;
    }

    this.currentFileChunks.push(new Uint8Array(rawData));
    this.emitProgress(undefined, this.activeReceiveFileIndex);
  }

  private handleFileEnd(payload: FileEndPayload): void {
    if (this.activeReceiveFileIndex === null || payload.fileIndex !== this.activeReceiveFileIndex) {
      this.handleError('Ricevuto FILE_END con fileIndex non valido o senza un FILE_START attivo');
      return;
    }

    // Verify byte counts coincide
    if (
      payload.totalBytes !== this.currentFileReceivedBytes ||
      payload.totalBytes !== this.currentFileTotalBytesExpected
    ) {
      this.handleError(
        `Discrepanza byte a FILE_END per file ${payload.fileIndex}: dichiarato ${payload.totalBytes}, atteso ${this.currentFileTotalBytesExpected}, ricevuti ${this.currentFileReceivedBytes}`
      );
      return;
    }

    // Assemble file
    const assembledFile = new Uint8Array(this.currentFileReceivedBytes);
    let offset = 0;
    for (const chunk of this.currentFileChunks) {
      assembledFile.set(chunk, offset);
      offset += chunk.length;
    }

    const itemOffer = this.remoteOfferItems[payload.fileIndex];

    // Verify magic bytes against declared MIME allowlist
    try {
      verifyMagicBytesForMime(assembledFile, itemOffer.mime);
    } catch (err: any) {
      this.handleError(`Validazione magic bytes fallita per file ${payload.fileIndex}: ${err.message}`);
      return;
    }

    // If salts already received, verify commitment
    if (this.remoteSalts) {
      const salt = this.remoteSalts[payload.fileIndex];
      const actualCommitment = calculateFileCommitment(salt, assembledFile);
      const actualHex = toHex(actualCommitment);

      if (actualHex.toLowerCase() !== itemOffer.commitment.toLowerCase()) {
        this.handleError(`Verifica fallita: il file ${payload.fileIndex} non corrisponde al commitment SHA-256!`);
        return;
      }
    }

    // Derive safe extension from MIME allowlist and create neutral file name
    const safeExtension = getSafeExtensionForMime(itemOffer.mime);
    const neutralName = generateIndexedNeutralFileName(payload.fileIndex, safeExtension);
    const blob = new Blob([assembledFile], { type: itemOffer.mime });

    const completedFile: CompletedFile = {
      name: neutralName,
      blob,
      mime: itemOffer.mime,
      size: assembledFile.length,
      data: assembledFile
    };

    // Keep file locked in RAM
    this.lockedReceivedFiles[payload.fileIndex] = completedFile;

    // Advance file pointer
    this.activeReceiveFileIndex = null;
    this.currentFileTotalBytesExpected = null;
    this.currentFileReceivedBytes = 0;
    this.currentFileChunks = [];
    this.expectedNextFileIndex++;

    // Check if all files in batch have been received
    if (this.expectedNextFileIndex === this.remoteOfferItems.length) {
      this.localReceiveDone = true;

      // Send BATCH_RECEIVE_COMPLETE
      this.sendControlMessage('BATCH_RECEIVE_COMPLETE', {
        confirmedItemCount: this.remoteOfferItems.length
      });

      this.checkReciprocalCompletion();
    }
  }

  private handleBatchReceiveComplete(payload: BatchReceiveCompletePayload): void {
    if (payload.confirmedItemCount !== this.localBatch.length) {
      this.handleError(
        `BATCH_RECEIVE_COMPLETE conteggio errato (dichiarati ${payload.confirmedItemCount}, attesi ${this.localBatch.length})`
      );
      return;
    }

    this.peerReceiveDone = true;
    this.checkReciprocalCompletion();
  }

  /**
   * Reciprocal Completion Gate:
   * Both parties unlock files ONLY when both localReceiveDone and peerReceiveDone are true,
   * and local sending is completed.
   */
  private checkReciprocalCompletion(): void {
    if (this.state === 'error' || this.isAborted) return;

    if (this.localReceiveDone) {
      if (!this.peerReceiveDone) {
        this.setState('waiting_peer_completion', 'Ricezione completata. In attesa del completamento del peer...');
      } else if (this.localSendDone || this.localBatch.length === 0) {
        // Both completed and confirmed!
        this.setState('completed', 'Scambio completato con successo!');
        for (const file of this.lockedReceivedFiles) {
          if (file) {
            this.onFileCompleted?.(file);
          }
        }
        this.onBatchCompleted?.(this.lockedReceivedFiles);
      }
    }
  }

  private emitProgress(currentSendingIndex?: number, currentReceivingIndex?: number): void {
    const totalToReceive = this.remoteOfferItems.reduce((acc, it) => acc + it.declaredMax, 0);
    const totalReceivedSoFar = this.lockedReceivedFiles.reduce((acc, f) => acc + (f ? f.size : 0), 0) + this.currentFileReceivedBytes;

    this.onProgress?.({
      bytesSent: this.bytesSent,
      totalToSend: this.totalBytesToSend,
      bytesReceived: totalReceivedSoFar,
      totalToReceive: totalToReceive || 1,
      currentSendingFileIndex: currentSendingIndex,
      currentReceivingFileIndex: currentReceivingIndex
    });
  }

  private sendControlMessage(type: string, payload: any): void {
    const jsonStr = JSON.stringify({ type, payload });
    const jsonBytes = new TextEncoder().encode(jsonStr);

    const plaintext = new Uint8Array(1 + jsonBytes.length);
    plaintext[0] = MSG_TYPE_CONTROL;
    plaintext.set(jsonBytes, 1);

    const ciphertext = this.noiseSession.encrypt(plaintext);
    this.sendRawData(ciphertext);
  }

  private handleError(message: string): void {
    // Immediate wipe of RAM buffers on error
    this.isAborted = true;
    this.lockedReceivedFiles = [];
    this.currentFileChunks = [];
    this.currentFileReceivedBytes = 0;
    this.activeReceiveFileIndex = null;
    this.localBatch = [];
    this.setState('error', message);
    this.onError?.(message);
  }
}
