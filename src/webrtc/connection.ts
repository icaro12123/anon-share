import { NoiseSession } from '../crypto/noise.ts';
import { NostrPostHandshakeTransport, ControlEnvelope } from '../nostr/postHandshake.ts';

export const STUN_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' }
];

export type WebRTCConnectionState =
  | 'sas_waiting'
  | 'sas_confirmed'
  | 'ice_gathering'
  | 'sdp_negotiation'
  | 'connecting'
  | 'connected'
  | 'failed'
  | 'closed';

export interface WebRTCConnectionOptions {
  isInitiator: boolean;
  noiseSession: NoiseSession;
  nostrTransport: NostrPostHandshakeTransport;
  onStateChange?: (state: WebRTCConnectionState, error?: string) => void;
  onDataChannelReady?: (dataChannel: RTCDataChannel) => void;
  onDataMessage?: (data: Uint8Array) => void;
}

/**
 * Manages Section 3.4 & 3.5 WebRTC P2P direct connection, non-trickle ICE, and DataChannel.
 */
export class WebRTCConnection {
  private isInitiator: boolean;
  private noiseSession: NoiseSession;
  private nostrTransport: NostrPostHandshakeTransport;
  private peerConnection: RTCPeerConnection | null = null;
  private dataChannel: RTCDataChannel | null = null;

  private state: WebRTCConnectionState = 'sas_waiting';
  private localSasConfirmed: boolean = false;
  private remoteSasConfirmed: boolean = false;

  private onStateChange?: (state: WebRTCConnectionState, error?: string) => void;
  private onDataChannelReady?: (dataChannel: RTCDataChannel) => void;
  private onDataMessage?: (data: Uint8Array) => void;

  private iceFailureTimer: ReturnType<typeof setTimeout> | null = null;
  private sasTimeoutTimer: ReturnType<typeof setTimeout> | null = null;
  private isClosed: boolean = false;

  constructor(options: WebRTCConnectionOptions) {
    this.isInitiator = options.isInitiator;
    this.noiseSession = options.noiseSession;
    this.nostrTransport = options.nostrTransport;
    this.onStateChange = options.onStateChange;
    this.onDataChannelReady = options.onDataChannelReady;
    this.onDataMessage = options.onDataMessage;

    // Start 5-minute SAS timeout per Section 3.4
    this.startSasTimeout();

    // Hook Nostr transport messages
    this.nostrTransport.setOnMessage((envelope) => this.handleNostrControlMessage(envelope));
  }

  private setState(newState: WebRTCConnectionState, error?: string): void {
    this.state = newState;
    this.onStateChange?.(newState, error);
  }

  public getState(): WebRTCConnectionState {
    return this.state;
  }

  private startSasTimeout(): void {
    // 5 minutes timeout per Section 3.4
    this.sasTimeoutTimer = setTimeout(() => {
      if (!this.localSasConfirmed || !this.remoteSasConfirmed) {
        this.close('Timeout verifica SAS scaduto (5 minuti)');
      }
    }, 5 * 60 * 1000);
  }

  /**
   * User clicks "Conferma" on the SAS verification gate.
   */
  public confirmSas(): void {
    if (this.localSasConfirmed) return;
    this.localSasConfirmed = true;

    // Notify remote peer via Nostr encrypted message
    this.nostrTransport.send('SAS_CONFIRMED', undefined, true);

    if (this.remoteSasConfirmed) {
      this.onBothSasConfirmed();
    } else {
      this.setState('sas_confirmed', 'In attesa della conferma del codice da parte del peer...');
    }
  }

  /**
   * User clicks "Annulla" on the SAS verification gate.
   */
  public cancelSas(): void {
    this.close('Scambio annullato durante la verifica del codice di sicurezza');
  }

  private handleNostrControlMessage(envelope: ControlEnvelope): void {
    if (this.isClosed) return;

    switch (envelope.type) {
      case 'SAS_CONFIRMED': {
        this.remoteSasConfirmed = true;
        if (this.localSasConfirmed) {
          this.nostrTransport.clearPendingOutgoing();
          this.onBothSasConfirmed();
        }
        break;
      }

      case 'SDP_OFFER': {
        if (!this.localSasConfirmed || !this.remoteSasConfirmed) {
          // Reject SDP before SAS gate per Section 3.2b rule 5 & 3.4
          return;
        }
        this.nostrTransport.clearPendingOutgoing();
        this.handleSdpOffer(envelope.payload);
        break;
      }

      case 'SDP_ANSWER': {
        if (!this.localSasConfirmed || !this.remoteSasConfirmed) {
          return;
        }
        this.nostrTransport.clearPendingOutgoing();
        this.handleSdpAnswer(envelope.payload);
        break;
      }
    }
  }

  private async onBothSasConfirmed(): Promise<void> {
    if (this.sasTimeoutTimer) {
      clearTimeout(this.sasTimeoutTimer);
      this.sasTimeoutTimer = null;
    }

    this.setState('sdp_negotiation', 'Codice di sicurezza verificato. Negoziazione diretta P2P...');
    await this.setupPeerConnection();

    if (this.isInitiator) {
      await this.startSdpOffer();
    }
  }

  private async setupPeerConnection(): Promise<void> {
    this.peerConnection = new RTCPeerConnection({
      iceServers: STUN_SERVERS
    });

    this.peerConnection.oniceconnectionstatechange = () => {
      const iceState = this.peerConnection?.iceConnectionState;
      if (iceState === 'connected' || iceState === 'completed') {
        if (this.iceFailureTimer) {
          clearTimeout(this.iceFailureTimer);
          this.iceFailureTimer = null;
        }
      } else if (iceState === 'failed' || iceState === 'disconnected') {
        this.startIceFailureTimer();
      }
    };

    if (this.isInitiator) {
      // Bob creates DataChannel with ordered & reliable
      this.dataChannel = this.peerConnection.createDataChannel('anonshare-dc', {
        ordered: true
      });
      this.setupDataChannel(this.dataChannel);
    } else {
      // Alice listens for DataChannel
      this.peerConnection.ondatachannel = (ev) => {
        this.dataChannel = ev.channel;
        this.setupDataChannel(this.dataChannel);
      };
    }
  }

  private setupDataChannel(channel: RTCDataChannel): void {
    channel.binaryType = 'arraybuffer';

    channel.onopen = async () => {
      this.setState('connecting', 'Canale diretto aperto. Verifica crittografica...');

      // Handshake test on DataChannel with DC_READY
      if (this.isInitiator) {
        // Initiator sends DC_READY ping encrypted with c1
        const pt = new Uint8Array([0x01, 0x44, 0x43]); // "DC"
        const ct = this.noiseSession.encrypt(pt);
        channel.send(ct as any);
      }
    };

    channel.onmessage = (event) => {
      const raw = new Uint8Array(event.data);
      if (this.state === 'connecting') {
        try {
          const pt = this.noiseSession.decrypt(raw);
          if (pt.length >= 3 && pt[0] === 0x01 && pt[1] === 0x44 && pt[2] === 0x43) {
            if (!this.isInitiator) {
              // Responder echoes DC_READY back
              const respPt = new Uint8Array([0x01, 0x44, 0x43]);
              const respCt = this.noiseSession.encrypt(respPt);
              channel.send(respCt as any);
            }

            // Both peers confirmed DC encryption!
            this.setState('connected', 'Connessione P2P cifrata stabilita con successo.');
            // Section 3.5.3: Disconnect Nostr now that DataChannel is active
            this.nostrTransport.close();
            this.onDataChannelReady?.(channel);
            return;
          }
        } catch {
          // Decryption failed
          return;
        }
      }

      // Deliver data message to protocol layer
      this.onDataMessage?.(raw);
    };

    channel.onerror = (err) => {
      this.close(`Errore nel DataChannel WebRTC: ${err}`);
    };

    channel.onclose = () => {
      if (this.state !== 'closed') {
        this.setState('closed', 'Connessione P2P terminata');
      }
    };
  }

  /**
   * Waits for non-trickle ICE candidate gathering to finish.
   */
  private async waitForIceGatheringComplete(pc: RTCPeerConnection): Promise<void> {
    if (pc.iceGatheringState === 'complete') return;

    await new Promise<void>((resolve) => {
      let resolved = false;
      const checkState = () => {
        if (pc.iceGatheringState === 'complete') {
          if (!resolved) {
            resolved = true;
            pc.removeEventListener('icegatheringstatechange', checkState);
            resolve();
          }
        }
      };

      pc.addEventListener('icegatheringstatechange', checkState);
      // Safety timeout (max 4 seconds for candidate gathering)
      setTimeout(() => {
        if (!resolved) {
          resolved = true;
          pc.removeEventListener('icegatheringstatechange', checkState);
          resolve();
        }
      }, 4000);
    });
  }

  private async startSdpOffer(): Promise<void> {
    if (!this.peerConnection) return;
    this.setState('ice_gathering', 'Raccolta indirizzi di rete per connessione diretta...');

    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);

    await this.waitForIceGatheringComplete(this.peerConnection);

    // Send complete non-trickle offer over Nostr c1
    const sdpPayload = JSON.stringify(this.peerConnection.localDescription);
    this.nostrTransport.send('SDP_OFFER', sdpPayload, true);
    this.startIceFailureTimer();
  }

  private async handleSdpOffer(offerJson: string): Promise<void> {
    if (!this.peerConnection) return;
    this.setState('ice_gathering', 'Ricevuta offerta di connessione. Preparazione risposta...');

    const offerDesc = new RTCSessionDescription(JSON.parse(offerJson));
    await this.peerConnection.setRemoteDescription(offerDesc);

    const answer = await this.peerConnection.createAnswer();
    await this.peerConnection.setLocalDescription(answer);

    await this.waitForIceGatheringComplete(this.peerConnection);

    const sdpPayload = JSON.stringify(this.peerConnection.localDescription);
    this.nostrTransport.send('SDP_ANSWER', sdpPayload, true);
    this.startIceFailureTimer();
  }

  private async handleSdpAnswer(answerJson: string): Promise<void> {
    if (!this.peerConnection) return;
    const answerDesc = new RTCSessionDescription(JSON.parse(answerJson));
    await this.peerConnection.setRemoteDescription(answerDesc);
  }

  private startIceFailureTimer(): void {
    if (this.iceFailureTimer) return;
    // 15 seconds timeout per Section 11 test 11 & Section 3.5.4
    this.iceFailureTimer = setTimeout(() => {
      if (this.state !== 'connected' && this.state !== 'closed') {
        this.close(
          'Impossibile stabilire connessione P2P diretta (NAT simmetrico restrittivo o assenza TURN).'
        );
      }
    }, 15000);
  }

  public sendData(data: Uint8Array): void {
    if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
      throw new Error('DataChannel is not open');
    }
    this.dataChannel.send(data as any);
  }

  public close(reason?: string): void {
    this.isClosed = true;
    if (this.sasTimeoutTimer) {
      clearTimeout(this.sasTimeoutTimer);
      this.sasTimeoutTimer = null;
    }
    if (this.iceFailureTimer) {
      clearTimeout(this.iceFailureTimer);
      this.iceFailureTimer = null;
    }

    try {
      this.dataChannel?.close();
    } catch {}

    try {
      this.peerConnection?.close();
    } catch {}

    this.nostrTransport.close();
    this.setState('closed', reason);
  }
}
