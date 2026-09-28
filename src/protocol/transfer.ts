import { NoiseSession } from '../crypto/noise.ts';
import { toHex, fromHex, calculateFileCommitment } from '../crypto/keys.ts';
import {
  MAX_FILE_SIZE_BYTES,
  generateNeutralFileName,
  SupportedMediaType
} from '../media/magic.ts';

export const CHUNK_SIZE = 16384; // 16 KiB per Section 6
export const MSG_TYPE_CONTROL = 0x01;
export const MSG_TYPE_DATA = 0x02;

export interface FileOffer {
  commitment: string; // hex
  blurhash?: string;
  declaredMax: number;
  mime: SupportedMediaType;
  extension: string;
}

export type TransferState =
  | 'idle'
  | 'file_selected'
  | 'offer_sent'
  | 'offer_received'
  | 'both_offered'
  | 'accepted_locally'
  | 'accepted_both'
  | 'streaming'
  | 'verifying'
  | 'completed'
  | 'error';

export interface TransferProgress {
  bytesSent: number;
  totalToSend: number;
  bytesReceived: number;
  totalToReceive: number;
}

export interface CompletedFile {
  name: string;
  blob: Blob;
  mime: string;
  size: number;
  data: Uint8Array;
}

export interface TransferProtocolOptions {
  isInitiator: boolean;
  noiseSession: NoiseSession;
  sendRawData: (data: Uint8Array) => void;
  onStateChange?: (state: TransferState, message?: string) => void;
  onOfferReceived?: (offer: FileOffer) => void;
  onProgress?: (progress: TransferProgress) => void;
  onFileCompleted?: (file: CompletedFile) => void;
  onError?: (error: string) => void;
}

/**
 * Implements Section 5 (The 3-stage exchange protocol) & Section 6 (Noise chunk streaming).
 */
export class TransferProtocol {
  public readonly isInitiator: boolean;
  private readonly noiseSession: NoiseSession;
  private readonly sendRawData: (data: Uint8Array) => void;

  private state: TransferState = 'idle';
  private isAborted: boolean = false;

  // Local file information
  private localFileBytes: Uint8Array | null = null;
  private localMime: SupportedMediaType | null = null;
  private localExtension: string | null = null;
  private localBlurhash: string | undefined;
  private localDeclaredMax: number = 0;
  private localSalt: Uint8Array | null = null;
  private localCommitment: Uint8Array | null = null;
  private localCommitmentHex: string = '';

  // Remote file information
  private remoteOffer: FileOffer | null = null;
  private remoteSalt: Uint8Array | null = null;
  private remoteReceivedChunks: Uint8Array[] = [];
  private remoteReceivedBytes: number = 0;
  private remoteTotalBytesExpected: number | null = null;

  // Consent flags
  private localAccepted: boolean = false;
  private remoteAccepted: boolean = false;
  private sendCompleted: boolean = false;
  private receiveCompleted: boolean = false;

  // Callbacks
  private onStateChange?: (state: TransferState, message?: string) => void;
  private onOfferReceived?: (offer: FileOffer) => void;
  private onProgress?: (progress: TransferProgress) => void;
  private onFileCompleted?: (file: CompletedFile) => void;
  private onError?: (error: string) => void;

  private bytesSent: number = 0;

  constructor(options: TransferProtocolOptions) {
    this.isInitiator = options.isInitiator;
    this.noiseSession = options.noiseSession;
    this.sendRawData = options.sendRawData;
    this.onStateChange = options.onStateChange;
    this.onOfferReceived = options.onOfferReceived;
    this.onProgress = options.onProgress;
    this.onFileCompleted = options.onFileCompleted;
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
    return this.remoteOffer;
  }

  /**
   * Stage 1: Prepares local file, generates salt, computes H, and sends Offer.
   */
  public prepareAndSendOffer(options: {
    cleanBytes: Uint8Array;
    mime: SupportedMediaType;
    extension: string;
    blurhash?: string;
    declaredMax: number;
  }): void {
    this.localFileBytes = options.cleanBytes;
    this.localMime = options.mime;
    this.localExtension = options.extension;
    this.localBlurhash = options.blurhash;
    this.localDeclaredMax = options.declaredMax;

    // 1. Generate random 32B salt
    this.localSalt = new Uint8Array(32);
    crypto.getRandomValues(this.localSalt);

    // 2. Compute commitment H = SHA256(salt || FilePulito)
    this.localCommitment = calculateFileCommitment(this.localSalt, this.localFileBytes);
    this.localCommitmentHex = toHex(this.localCommitment);

    // 3. Send OFFER (NO SALT)
    const offerPayload: FileOffer = {
      commitment: this.localCommitmentHex,
      blurhash: this.localBlurhash,
      declaredMax: this.localDeclaredMax,
      mime: this.localMime,
      extension: this.localExtension
    };

    this.sendControlMessage('OFFER', offerPayload);

    if (this.remoteOffer) {
      this.setState('both_offered', 'Entrambe le anteprime sono pronte per la verifica');
    } else {
      this.setState('offer_sent', 'Offerta inviata. In attesa del file della controparte...');
    }
  }

  /**
   * Stage 2: User clicks "Accetta Scambio".
   */
  public acceptExchange(): void {
    if (!this.localCommitmentHex || !this.remoteOffer) {
      throw new Error('Impossibile accettare prima di aver scambiato le offerte');
    }
    this.localAccepted = true;

    // Send ACCEPT { commitmentA, commitmentB }
    const payload = {
      myCommitment: this.localCommitmentHex,
      peerCommitment: this.remoteOffer.commitment
    };
    this.sendControlMessage('ACCEPT', payload);

    if (this.remoteAccepted) {
      this.startStage3Streaming();
    } else {
      this.setState('accepted_locally', 'Hai accettato lo scambio. In attesa del consenso del peer...');
    }
  }

  /**
   * Stage 3: Revelation of salt, streaming DATA chunks, and MSG_FILE_END.
   */
  private async startStage3Streaming(): Promise<void> {
    if (this.isAborted) return;
    this.setState('accepted_both', 'Doppio consenso verificato. Avvio trasferimento...');

    if (!this.localSalt || !this.localFileBytes) {
      return;
    }

    // 1. Send MSG_SALT { salt }
    this.sendControlMessage('SALT', { salt: toHex(this.localSalt) });

    if (this.isAborted) return;
    this.setState('streaming', 'Trasferimento dati cifrati in corso...');

    // 2. Stream DATA chunks (16 KiB each, prefixed with 0x02)
    const totalBytes = this.localFileBytes.length;
    let offset = 0;
    this.bytesSent = 0;

    while (offset < totalBytes) {
      if (this.isAborted) return;
      const end = Math.min(offset + CHUNK_SIZE, totalBytes);
      const chunk = this.localFileBytes.subarray(offset, end);

      const plaintext = new Uint8Array(1 + chunk.length);
      plaintext[0] = MSG_TYPE_DATA;
      plaintext.set(chunk, 1);

      // Encrypt with Noise transport
      const ciphertext = this.noiseSession.encrypt(plaintext);
      this.sendRawData(ciphertext);

      offset = end;
      this.bytesSent = offset;
      this.emitProgress();

      // Yield event loop briefly every few chunks to prevent freezing UI
      if (offset % (CHUNK_SIZE * 8) === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    if (this.isAborted) return;

    // 3. Send MSG_FILE_END { totalBytes }
    this.sendControlMessage('FILE_END', { totalBytes });
    this.sendCompleted = true;
    this.checkBothCompleted();
  }

  /**
   * Handles incoming raw message from WebRTC DataChannel.
   */
  public handleIncomingMessage(rawCiphertext: Uint8Array): void {
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
      case 'OFFER': {
        const offer = data.payload as FileOffer;
        // Validate declaredMax
        if (!offer.declaredMax || offer.declaredMax > MAX_FILE_SIZE_BYTES) {
          this.handleError('Offerta remota non valida: dimensione eccede 100 MB');
          return;
        }

        this.remoteOffer = offer;
        this.onOfferReceived?.(offer);

        if (this.localCommitmentHex) {
          this.setState('both_offered', 'Offerte scambiate con successo. Verifica anteprima prima di accettare');
        } else {
          this.setState('offer_received', 'Ricevuta offerta dal peer. Seleziona il tuo file da scambiare');
        }
        break;
      }

      case 'ACCEPT': {
        const { myCommitment, peerCommitment } = data.payload;
        // Section 5: Verify commitments match current offers
        if (
          !this.remoteOffer ||
          myCommitment !== this.remoteOffer.commitment ||
          peerCommitment !== this.localCommitmentHex
        ) {
          this.handleError('Discrepanza nei commitment di doppio consenso');
          return;
        }

        this.remoteAccepted = true;
        if (this.localAccepted) {
          this.startStage3Streaming();
        }
        break;
      }

      case 'SALT': {
        try {
          this.remoteSalt = fromHex(data.payload.salt);
          if (this.remoteSalt.length !== 32) {
            this.handleError('Salt ricevuto non valido (lunghezza errata)');
            return;
          }
          this.checkCompletion();
        } catch {
          this.handleError('Salt remoto non decodificabile');
        }
        break;
      }

      case 'FILE_END': {
        this.remoteTotalBytesExpected = data.payload.totalBytes;
        this.checkCompletion();
        break;
      }
    }
  }

  private handleDataChunk(chunk: Uint8Array): void {
    if (!this.remoteOffer) {
      this.handleError('Ricevuto blocco dati prima dell offerta');
      return;
    }

    this.remoteReceivedBytes += chunk.length;

    // Section 8: Controlli Dimensionali
    if (this.remoteReceivedBytes > this.remoteOffer.declaredMax) {
      this.handleError(
        `Byte ricevuti (${this.remoteReceivedBytes}) superano il limite dichiarato (${this.remoteOffer.declaredMax})`
      );
      return;
    }
    if (this.remoteReceivedBytes > MAX_FILE_SIZE_BYTES) {
      this.handleError('Tetto massimo di 100 MB superato');
      return;
    }

    this.remoteReceivedChunks.push(new Uint8Array(chunk));
    this.emitProgress();
    this.checkCompletion();
  }

  /**
   * Validates Section 5 checks upon arrival of all chunks, SALT, and FILE_END.
   */
  private checkCompletion(): void {
    if (this.remoteTotalBytesExpected === null || !this.remoteSalt) {
      return;
    }

    if (this.remoteReceivedBytes < this.remoteTotalBytesExpected) {
      return;
    }

    this.setState('verifying', 'Verifica integrità e commitment SHA-256...');

    // 1. Check total_bytes == ricevuti
    if (this.remoteReceivedBytes !== this.remoteTotalBytesExpected) {
      this.handleError(
        `Discrepanza byte: dichiarati ${this.remoteTotalBytesExpected}, ricevuti ${this.remoteReceivedBytes}`
      );
      return;
    }

    // Assemble file
    const assembledFile = new Uint8Array(this.remoteReceivedBytes);
    let offset = 0;
    for (const chunk of this.remoteReceivedChunks) {
      assembledFile.set(chunk, offset);
      offset += chunk.length;
    }

    // 2. Verify H == SHA256(salt || File)
    const actualCommitment = calculateFileCommitment(this.remoteSalt, assembledFile);
    const actualHex = toHex(actualCommitment);

    if (actualHex !== this.remoteOffer!.commitment) {
      this.handleError('Verifica fallita: il file ricevuto non corrisponde al commitment H!');
      return;
    }

    // Success! Generate neutral filename per Section 8
    const neutralName = generateNeutralFileName(this.remoteOffer!.extension);
    const blob = new Blob([assembledFile], { type: this.remoteOffer!.mime });

    this.receiveCompleted = true;
    this.onFileCompleted?.({
      name: neutralName,
      blob,
      mime: this.remoteOffer!.mime,
      size: assembledFile.length,
      data: assembledFile
    });
    this.checkBothCompleted();
  }

  private checkBothCompleted(): void {
    if (this.state === 'error') return;
    if (this.receiveCompleted && (this.sendCompleted || !this.localFileBytes)) {
      this.setState('completed', 'Scambio completato con successo!');
    }
  }

  private emitProgress(): void {
    this.onProgress?.({
      bytesSent: this.bytesSent,
      totalToSend: this.localFileBytes ? this.localFileBytes.length : 0,
      bytesReceived: this.remoteReceivedBytes,
      totalToReceive: this.remoteTotalBytesExpected ?? (this.remoteOffer?.declaredMax || 0)
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
    // Zero out memory buffers on error per Section 8
    this.isAborted = true;
    this.remoteReceivedChunks = [];
    this.remoteReceivedBytes = 0;
    this.localFileBytes = null;
    this.setState('error', message);
    this.onError?.(message);
  }
}
