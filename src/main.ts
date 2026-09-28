import './style.css';
import { decode as decodeBlurhash } from 'blurhash';
import {
  generateRoomSecret,
  deriveDirectKeys,
  deriveSasWords,
  toHex,
  fromHex
} from './crypto/keys.ts';
import { NoiseSession, NoiseHandshakeResult } from './crypto/noise.ts';
import { NostrRelayPool, NostrIdentity } from './nostr/nostr.ts';
import { NostrHandshakeManager } from './nostr/handshake.ts';
import { NostrPostHandshakeTransport } from './nostr/postHandshake.ts';
import { WebRTCConnection } from './webrtc/connection.ts';
import { sanitizeMediaFile, SanitizedMedia } from './media/sanitize.ts';
import {
  TransferProtocol,
  OfferItemPayload,
  CompletedFile,
  TransferProgress
} from './protocol/transfer.ts';
import {
  formatBytes,
  MAX_BATCH_FILES,
  validateBatchSelection
} from './media/magic.ts';
import { initStarfield, getStarfield } from './ui/starfield.ts';

// PWA Service Worker Registration
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

// Initialize ASCII Starfield Canvas in Background
initStarfield('bg-starfield');

const appEl = document.getElementById('app')!;

// Navigation & URL parsing
function checkRoute(): { isTorMode: boolean; directSecret: Uint8Array | null } {
  const path = window.location.pathname;
  const hash = window.location.hash;

  // Section 2: Strict behavior on Tor links
  if (path.startsWith('/t/') || path === '/t' || hash.includes('onion=')) {
    // Remove fragment immediately from history and URL bar
    window.history.replaceState(null, '', '/t/');
    return { isTorMode: true, directSecret: null };
  }

  // Direct Mode link: #direct&secret=<hex>
  if (hash.includes('secret=')) {
    const params = new URLSearchParams(hash.replace(/^#/, ''));
    const secretHex = params.get('secret');
    window.history.replaceState(null, '', window.location.pathname);

    if (secretHex) {
      try {
        const secret = fromHex(secretHex);
        if (secret.length === 32) {
          return { isTorMode: false, directSecret: secret };
        }
      } catch {}
    }
  }

  return { isTorMode: false, directSecret: null };
}

// App State
let pool: NostrRelayPool | null = null;
let identity: NostrIdentity | null = null;
let handshakeManager: NostrHandshakeManager | null = null;
let postTransport: NostrPostHandshakeTransport | null = null;
let webrtcConn: WebRTCConnection | null = null;
let transferProto: TransferProtocol | null = null;
let noiseSession: NoiseSession | null = null;

let localRawFiles: Map<string, File> = new Map();
let localSanitizedFiles: SanitizedMedia[] = [];
let remoteOfferItems: OfferItemPayload[] = [];
let sasTimerInterval: ReturnType<typeof setInterval> | null = null;
let sasSecondsRemaining = 300; // 5 minutes

// UI Views
function renderHeader() {
  const sf = getStarfield();
  const isFxActive = sf ? sf.isActive() : true;

  return `
    <header>
      <div class="header-top-row">
        <div class="logo-title">
          <svg class="logo-icon" viewBox="0 0 512 512" fill="none">
            <circle cx="256" cy="256" r="220" stroke="var(--primary)" stroke-width="24" stroke-dasharray="24 24"/>
            <path d="M256 140 V256 L340 340" stroke="var(--primary-light)" stroke-width="28" stroke-linecap="round"/>
            <circle cx="256" cy="256" r="36" fill="var(--primary)"/>
          </svg>
          <span>AnonShare</span>
        </div>
        <div class="header-actions">
          <div class="badge badge-direct">⚡ P2P Direct</div>
          <button id="btn-toggle-fx" class="fx-toggle-btn ${isFxActive ? '' : 'off'}" title="Attiva/Disattiva Starfield ASCII">
            <span>${isFxActive ? '✶ FX ON' : '✶ FX OFF'}</span>
          </button>
        </div>
      </div>
    </header>
  `;
}

function bindHeaderEvents() {
  const fxBtn = document.getElementById('btn-toggle-fx');
  if (fxBtn) {
    fxBtn.onclick = () => {
      const sf = getStarfield();
      const active = sf?.toggle() ?? false;
      fxBtn.classList.toggle('off', !active);
      fxBtn.innerHTML = `<span>${active ? '✶ FX ON' : '✶ FX OFF'}</span>`;
    };
  }
}

/**
 * Section 2: Rigorous static Tor link screen with ZERO network activity.
 */
function renderTorStaticScreen() {
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card" style="text-align: center;">
      <div class="terminal-sub">>_ TOR ONION TRANSPORT</div>
      <div class="card-title" style="margin-top: 4px;">Modalità Tor Richiesta</div>
      <div class="alert-info" style="font-size: 0.95rem; padding: 14px;">
        Questo scambio richiede l'app Android in modalità Tor.<br/>
        Apri il link sull'app <strong>AnonShare</strong> per scambiare il batch di file.
      </div>
      <p class="text-sm">
        La versione Web non esegue Tor onion services per preservare il massimo anonimato. Nessuna connessione di rete è stata aperta dal tuo browser.
      </p>
      <a href="/" class="btn btn-secondary btn-block">Torna alla Modalità Diretta</a>
    </div>
  `;
  bindHeaderEvents();
}

function renderHomeScreen() {
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="twin-hub-grid">
      <!-- Card 1: Crea Stanza -->
      <div class="twin-card">
        <div class="twin-card-header">
          <div class="twin-card-icon">
            <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 4v16m8-8H4"></path></svg>
          </div>
          <div>
            <div class="terminal-sub">>_ NUOVA SESSIONE</div>
            <div class="card-title" style="font-size: 1.05rem;">Crea Stanza P2P</div>
          </div>
        </div>
        <div class="twin-card-body">
          <p class="text-sm">
            Genera un link monouso crittografato end-to-end con protocollo Noise NNpsk0 per scambiare file direttamente dal browser.
          </p>
        </div>
        <button id="btn-create-room" class="btn btn-primary btn-block">
          Crea Stanza
        </button>
      </div>

      <!-- Card 2: Partecipa con Link -->
      <div class="twin-card">
        <div class="twin-card-header">
          <div class="twin-card-icon" style="background: rgba(56, 189, 248, 0.12); border-color: rgba(56, 189, 248, 0.3); color: var(--ice-cyan);">
            <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
          </div>
          <div>
            <div class="terminal-sub">>_ RICEVI O UNISCITI</div>
            <div class="card-title" style="font-size: 1.05rem;">Partecipa con Link</div>
          </div>
        </div>
        <div class="twin-card-body">
          <p class="text-sm">
            Incolla il link condiviso o il segreto esadecimale a 256-bit per avviare la negoziazione diretta.
          </p>
        </div>
        <div class="input-group">
          <input type="text" id="input-join-link" placeholder="Incolla link o segreto..." autocomplete="off" spellcheck="false" />
          <button id="btn-join-room" class="btn btn-secondary" style="min-width: 80px;">Entra</button>
        </div>
      </div>
    </div>

    <!-- Security & Privacy Banner -->
    <div class="privacy-audit-card">
      <div class="privacy-audit-header" id="privacy-audit-toggle">
        <div class="privacy-audit-label">
          <span style="color: var(--status-success); font-size: 0.8rem; flex-shrink: 0;">●</span>
          <span class="privacy-text-full">Zero Server · Cifratura Noise NNpsk0 · Bonifica Metadati EXIF</span>
          <span class="privacy-text-compact">Zero Server · Noise E2EE · No Log</span>
        </div>
        <span id="privacy-toggle-icon" class="privacy-toggle-badge">[INFO ▼]</span>
      </div>
      <div id="privacy-audit-content" style="display: none; line-height: 1.45; color: var(--text-muted); font-size: 0.78rem; border-top: 1px solid var(--border-subtle); padding-top: 8px; margin-top: 4px;">
        In Modalità Diretta, WebRTC connette direttamente i due partecipanti. I peer e i relay Nostr vedono gli indirizzi IP durante la negoziazione. Per proteggere il tuo indirizzo IP a livello di rete, usa una VPN di sistema.
      </div>
    </div>
  `;

  bindHeaderEvents();

  const toggle = document.getElementById('privacy-audit-toggle');
  const content = document.getElementById('privacy-audit-content');
  const toggleIcon = document.getElementById('privacy-toggle-icon');
  if (toggle && content && toggleIcon) {
    toggle.onclick = () => {
      const isHidden = content.style.display === 'none';
      content.style.display = isHidden ? 'block' : 'none';
      toggleIcon.textContent = isHidden ? '[CHIUDI ▲]' : '[INFO ▼]';
    };
  }

  document.getElementById('btn-create-room')!.onclick = () => {
    const roomSecret = generateRoomSecret();
    startRoomSession(roomSecret, false); // false = Alice (Creator / Responder)
  };

  document.getElementById('btn-join-room')!.onclick = () => {
    const val = (document.getElementById('input-join-link') as HTMLInputElement).value.trim();
    if (!val) return;
    let secretBytes: Uint8Array | null = null;
    try {
      if (val.includes('secret=')) {
        const hashPart = val.split('#')[1] || val;
        const params = new URLSearchParams(hashPart);
        const sec = params.get('secret');
        if (sec) secretBytes = fromHex(sec);
      } else {
        secretBytes = fromHex(val);
      }
    } catch {}

    if (secretBytes && secretBytes.length === 32) {
      startRoomSession(secretBytes, true); // true = Bob (Participant / Initiator)
    } else {
      alert('Segreto stanza o link non valido (deve contenere 32 byte esadecimali)');
    }
  };
}

function startRoomSession(roomSecret: Uint8Array, isInitiator: boolean) {
  const { noisePsk, roomTag } = deriveDirectKeys(roomSecret);
  const secretHex = toHex(roomSecret);
  const roomUrl = `${window.location.origin}/#direct&secret=${secretHex}`;

  identity = new NostrIdentity();
  pool = new NostrRelayPool();
  pool.connect();

  if (!isInitiator) {
    renderWaitingScreen(roomUrl, roomTag);
  } else {
    renderInitiatingScreen();
  }

  handshakeManager = new NostrHandshakeManager({
    isInitiator,
    psk: noisePsk,
    roomTag,
    pool,
    identity,
    onStatusChange: (_status, msg) => {
      const statusEl = document.getElementById('handshake-status-text');
      if (statusEl && msg) statusEl.textContent = msg;
    },
    onHandshakeComplete: (result) => {
      onHandshakeCompleted(result, isInitiator, roomTag);
    }
  });

  handshakeManager.start();
}

function renderWaitingScreen(roomUrl: string, roomTag: string) {
  const hasNativeShare = typeof navigator !== 'undefined' && !!navigator.share;

  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card">
      <div>
        <div class="terminal-sub">>_ HANDSHAKE IN ASCOLTO</div>
        <div class="card-title" style="margin-top: 4px;">Stanza Creata — In Attesa del Peer</div>
        <p class="text-sm" style="margin-top: 6px;">
          Condividi questo link temporaneo monouso con la persona con cui desideri scambiare i file:
        </p>
      </div>

      <div class="input-group">
        <input type="text" readonly value="${roomUrl}" id="room-url-input" />
        <button class="btn btn-secondary" id="btn-copy-url">Copia</button>
      </div>

      ${
        hasNativeShare
          ? `<button id="btn-share-url" class="btn btn-primary btn-block">
               <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8m-4-6l-4-4m0 0l-4 4m4-4v12"></path></svg>
               Condividi Link (WhatsApp, Telegram...)
             </button>`
          : ''
      }

      <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: var(--bg-subtle); border: 1px solid var(--border-color); border-radius: var(--radius);">
        <div class="pulse" style="width: 10px; height: 10px; border-radius: 50%; background: var(--primary); flex-shrink: 0;"></div>
        <span class="text-sm" id="handshake-status-text" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--ice-frost);">
          In ascolto sui relay Nostr pubblici...
        </span>
      </div>

      <div class="text-sm" style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">
        ROOM TAG: ${roomTag.substring(0, 16)}...
      </div>

      <button id="btn-cancel-session" class="btn btn-danger btn-block">Annulla Stanza</button>
    </div>
  `;

  bindHeaderEvents();

  document.getElementById('btn-copy-url')!.onclick = () => {
    navigator.clipboard.writeText(roomUrl);
    const btn = document.getElementById('btn-copy-url')!;
    btn.textContent = 'Copiato!';
    setTimeout(() => (btn.textContent = 'Copia'), 2000);
  };

  const shareBtn = document.getElementById('btn-share-url');
  if (shareBtn) {
    shareBtn.onclick = async () => {
      try {
        await navigator.share({
          title: 'AnonShare P2P',
          text: 'Unisciti alla stanza anonima per lo scambio file:',
          url: roomUrl
        });
      } catch {}
    };
  }

  document.getElementById('btn-cancel-session')!.onclick = () => {
    resetToHome();
  };
}

function renderInitiatingScreen() {
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card" style="text-align: center;">
      <div class="terminal-sub">>_ HANDSHAKE NOISE NNPSK0</div>
      <div class="card-title" style="margin-top: 4px;">Connessione alla Stanza...</div>
      <div style="display: flex; justify-content: center; margin: 1.5rem 0;">
        <div class="pulse" style="width: 28px; height: 28px; border-radius: 50%; background: var(--primary); box-shadow: 0 0 16px rgba(99, 102, 241, 0.6);"></div>
      </div>
      <p class="text-sm" id="handshake-status-text" style="font-family: var(--font-mono); color: var(--ice-frost);">
        Invio richiesta di handshake cifrato Noise NNpsk0...
      </p>
      <button id="btn-cancel-session" class="btn btn-danger btn-block" style="margin-top: 1rem;">Annulla</button>
    </div>
  `;

  bindHeaderEvents();

  document.getElementById('btn-cancel-session')!.onclick = () => {
    resetToHome();
  };
}

function onHandshakeCompleted(result: NoiseHandshakeResult, isInitiator: boolean, roomTag: string) {
  noiseSession = new NoiseSession(isInitiator, result);
  const sasWords = deriveSasWords(result.h);

  postTransport = new NostrPostHandshakeTransport({
    roomTag,
    pool: pool!,
    identity: identity!,
    noiseSession
  });

  webrtcConn = new WebRTCConnection({
    isInitiator,
    noiseSession,
    nostrTransport: postTransport,
    onStateChange: (state, error) => {
      const msgEl = document.getElementById('webrtc-state-text');
      if (msgEl) msgEl.textContent = error || state;
      if (state === 'failed') {
        alert(error || 'Connessione WebRTC fallita');
        resetToHome();
      }
    },
    onDataChannelReady: () => {
      onDataChannelEstablished(isInitiator);
    }
  });

  renderSasGate(sasWords);
}

function renderSasGate(sasWords: string[]) {
  sasSecondsRemaining = 300;
  if (sasTimerInterval) clearInterval(sasTimerInterval);

  sasTimerInterval = setInterval(() => {
    sasSecondsRemaining--;
    const timerEl = document.getElementById('sas-timer');
    if (timerEl) {
      const mins = Math.floor(sasSecondsRemaining / 60);
      const secs = sasSecondsRemaining % 60;
      timerEl.textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
    }
    if (sasSecondsRemaining <= 0) {
      clearInterval(sasTimerInterval!);
      alert('Tempo scaduto per la verifica del codice di sicurezza SAS (5 minuti)');
      resetToHome();
    }
  }, 1000);

  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <div class="terminal-sub">>_ SECURITY VAULT</div>
          <div class="card-title" style="margin-top: 4px;">Verifica di Sicurezza SAS</div>
        </div>
        <div class="badge badge-direct" style="font-size: 0.8rem;">
          ⏱️ <span id="sas-timer" style="color: var(--status-warning-text); font-family: var(--font-mono); font-weight: 700;">5:00</span>
        </div>
      </div>
      
      <div class="alert-warning">
        <strong>Confronto Vocale Fuori Banda:</strong> Confronta queste 6 parole a voce o in chiamata prima di procedere. Nessun dato viene scambiato prima della verifica.
      </div>

      <div class="sas-grid">
        ${sasWords
          .map(
            (word, idx) => `
          <div class="sas-word-box">
            <span class="sas-word-num">PAROLA ${String(idx + 1).padStart(2, '0')}</span>
            <span class="sas-word-val">${word}</span>
          </div>
        `
          )
          .join('')}
      </div>

      <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 4px;">
        <button id="btn-confirm-sas" class="btn btn-success btn-block" style="min-height: 48px;">
          ✓ Confermo Corrispondenza
        </button>
        <button id="btn-cancel-sas" class="btn btn-secondary btn-block">
          ✕ Annulla Sessione
        </button>
      </div>

      <p class="text-sm" id="webrtc-state-text" style="text-align: center; color: var(--text-muted); margin-top: 4px; font-family: var(--font-mono); font-size: 0.78rem;">
        In attesa della tua conferma...
      </p>
    </div>
  `;

  bindHeaderEvents();

  document.getElementById('btn-confirm-sas')!.onclick = () => {
    webrtcConn?.confirmSas();
    const btn = document.getElementById('btn-confirm-sas') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = '✓ Confermato (In attesa del peer...)';
  };

  document.getElementById('btn-cancel-sas')!.onclick = () => {
    webrtcConn?.cancelSas();
    resetToHome();
  };
}

function onDataChannelEstablished(isInitiator: boolean) {
  if (sasTimerInterval) clearInterval(sasTimerInterval);

  transferProto = new TransferProtocol({
    isInitiator,
    noiseSession: noiseSession!,
    sendRawData: (data) => webrtcConn?.sendData(data),
    onBatchOfferReceived: (items) => {
      remoteOfferItems = items;
      renderRemoteOfferGrid();
    },
    onStateChange: (state, msg) => {
      const stateEl = document.getElementById('transfer-status-text');
      if (stateEl && msg) stateEl.textContent = msg;

      if (state === 'both_offered') {
        const acceptBtn = document.getElementById('btn-accept-exchange') as HTMLButtonElement;
        if (acceptBtn) {
          acceptBtn.disabled = false;
          acceptBtn.textContent = `Accetta Scambio (${remoteOfferItems.length} file dal peer)`;
        }
      } else if (state === 'waiting_peer_completion') {
        renderWaitingReciprocalScreen();
      }
    },
    onProgress: (prog) => {
      updateProgressBar(prog);
    },
    onBatchCompleted: (completedFiles) => {
      renderCompletedScreen(completedFiles);
    },
    onError: (err) => {
      alert(`Errore scambio: ${err}`);
      resetToHome();
    }
  });

  webrtcConn?.setOnDataMessage((data) => {
    transferProto?.handleIncomingMessage(data);
  });

  renderTransferScreen();
}

function renderTransferScreen() {
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card" style="padding: 18px;">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div class="terminal-sub">>_ CANALE DIRETTO WEBRTC</div>
          <span class="card-title">Scambio Bilaterale Multi-Media</span>
        </div>
        <span class="badge badge-success">E2EE Connesso</span>
      </div>

      <!-- Bilateral Deck (Side-by-side on desktop >= 768px, stacked on mobile < 768px) -->
      <div class="bilateral-deck">
        <!-- Column 1: Local Outgoing Batch -->
        <div class="deck-column" id="local-batch-panel">
          <div class="deck-header">
            <span class="deck-title">📤 I Tuoi File (<span id="local-files-count">0</span>)</span>
            <span id="local-batch-total-size" class="text-sm" style="font-family: var(--font-mono); font-size: 0.75rem;">0 B / 100 MB</span>
          </div>

          <!-- File Dropzone -->
          <div id="file-dropzone" class="dropzone">
            <svg width="32" height="32" fill="none" stroke="currentColor" stroke-width="1.75" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
            </svg>
            <div>
              <strong style="color: var(--text-primary); font-size: 0.9rem;">Trascina file</strong> o tocca per sfogliare
              <div class="text-sm" style="font-size: 0.72rem; margin-top: 2px;">Fino a 50 file (Foto, Video, Audio - Max 100 MB)</div>
            </div>
            <input type="file" id="file-input" multiple style="display: none;" accept="image/*,video/mp4,video/webm,audio/mpeg,audio/flac" />
          </div>

          <div id="sanitizing-indicator" style="display: none;" class="alert-info">
            <div class="pulse">Sanificazione metadati in corso...</div>
          </div>

          <!-- Local Selection List -->
          <div id="local-batch-section" style="display: none; flex-direction: column; gap: 8px;">
            <div id="local-batch-list" class="file-scroll-area"></div>
            <button id="btn-send-offer" class="btn btn-primary btn-block">Invia Offerta Batch al Peer</button>
          </div>
        </div>

        <!-- Column 2: Remote Incoming Batch -->
        <div class="deck-column" id="remote-batch-panel">
          <div class="deck-header">
            <span class="deck-title">📥 File del Peer (<span id="remote-files-count">0</span>)</span>
            <span id="remote-batch-total-size" class="text-sm" style="font-family: var(--font-mono); font-size: 0.75rem;"></span>
          </div>

          <div id="remote-batch-section" style="display: flex; flex-direction: column; gap: 8px;">
            <div id="remote-batch-grid" class="remote-grid">
              <div style="grid-column: 1 / -1; padding: 24px 12px; text-align: center; color: var(--text-muted); font-size: 0.8rem; border: 1px dashed var(--border-color); border-radius: var(--radius);">
                In attesa che il peer selezioni e invii l'offerta dei suoi file...
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Sticky Bottom Action Dock -->
      <div class="exchange-dock">
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <button id="btn-accept-exchange" class="btn btn-success btn-block" disabled>
            In attesa dello scambio delle offerte...
          </button>
          <span id="transfer-status-text" class="text-sm" style="text-align: center; font-family: var(--font-mono); font-size: 0.78rem;">
            Seleziona uno o più file per avviare lo scambio.
          </span>
        </div>

        <!-- Progress Section -->
        <div id="progress-section" style="display: none; flex-direction: column; gap: 10px;">
          <div class="progress-container">
            <div style="display: flex; justify-content: space-between;" class="text-sm">
              <span style="font-family: var(--font-mono); font-size: 0.75rem;">Invio Dati Cifrati</span>
              <span id="send-progress-pct" style="font-family: var(--font-mono); font-weight: 600; font-size: 0.75rem; color: var(--ice-cyan);">0%</span>
            </div>
            <div class="progress-bar-bg"><div id="send-progress-bar" class="progress-bar-fill" style="width: 0%;"></div></div>
          </div>

          <div class="progress-container">
            <div style="display: flex; justify-content: space-between;" class="text-sm">
              <span style="font-family: var(--font-mono); font-size: 0.75rem;">Ricezione Dati Cifrati</span>
              <span id="recv-progress-pct" style="font-family: var(--font-mono); font-weight: 600; font-size: 0.75rem; color: var(--ice-cyan);">0%</span>
            </div>
            <div class="progress-bar-bg"><div id="recv-progress-bar" class="progress-bar-fill" style="width: 0%;"></div></div>
          </div>
        </div>
      </div>
    </div>
  `;

  bindHeaderEvents();

  const dropzone = document.getElementById('file-dropzone')!;
  const fileInput = document.getElementById('file-input') as HTMLInputElement;

  dropzone.onclick = () => fileInput.click();
  fileInput.onchange = async () => {
    if (fileInput.files && fileInput.files.length > 0) {
      await handleFilesAdded(Array.from(fileInput.files));
      fileInput.value = '';
    }
  };

  dropzone.ondragover = (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  };
  dropzone.ondragleave = () => dropzone.classList.remove('dragover');
  dropzone.ondrop = async (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer?.files && e.dataTransfer.files.length > 0) {
      await handleFilesAdded(Array.from(e.dataTransfer.files));
    }
  };

  document.getElementById('btn-send-offer')!.onclick = () => {
    sendLocalBatchOffer();
  };

  document.getElementById('btn-accept-exchange')!.onclick = () => {
    try {
      transferProto?.acceptExchange();
      const btn = document.getElementById('btn-accept-exchange') as HTMLButtonElement;
      btn.disabled = true;
      btn.textContent = 'Hai Accettato (In attesa del consenso del peer...)';
    } catch (err: any) {
      alert(err.message);
    }
  };

  // Re-render local and remote if already present
  if (localSanitizedFiles.length > 0) renderLocalBatchList();
  if (remoteOfferItems.length > 0) renderRemoteOfferGrid();
}

async function handleFilesAdded(newFiles: File[]) {
  if (localSanitizedFiles.length + newFiles.length > MAX_BATCH_FILES) {
    alert(`Puoi selezionare al massimo ${MAX_BATCH_FILES} file per batch.`);
    return;
  }

  const allFiles = [...localSanitizedFiles.map((s) => ({ size: s.cleanBytes.length })), ...newFiles];
  try {
    validateBatchSelection(allFiles);
  } catch (err: any) {
    alert(err.message);
    return;
  }

  const sanitizeInd = document.getElementById('sanitizing-indicator');
  if (sanitizeInd) sanitizeInd.style.display = 'block';

  try {
    for (const file of newFiles) {
      const sanitized = await sanitizeMediaFile(file, 'blurhash');
      const fileId = sanitized.id || crypto.randomUUID();
      sanitized.id = fileId;
      localRawFiles.set(fileId, file);
      localSanitizedFiles.push(sanitized);
    }
  } catch (err: any) {
    alert(`Errore elaborazione file: ${err.message}`);
  } finally {
    if (sanitizeInd) sanitizeInd.style.display = 'none';
  }

  renderLocalBatchList();
}

function renderLocalBatchList() {
  const section = document.getElementById('local-batch-section');
  const countEl = document.getElementById('local-files-count');
  const totalSizeEl = document.getElementById('local-batch-total-size');
  const listEl = document.getElementById('local-batch-list');
  const mobCount = document.getElementById('mobile-local-count');

  if (mobCount) mobCount.textContent = String(localSanitizedFiles.length);
  if (!section || !countEl || !totalSizeEl || !listEl) return;

  if (localSanitizedFiles.length === 0) {
    section.style.display = 'none';
    countEl.textContent = '0';
    totalSizeEl.textContent = '0 B / 100 MB';
    return;
  }

  section.style.display = 'flex';
  countEl.textContent = String(localSanitizedFiles.length);
  const totalBytes = localSanitizedFiles.reduce((acc, f) => acc + f.cleanBytes.length, 0);
  totalSizeEl.textContent = `${formatBytes(totalBytes)} / 100 MB`;

  listEl.innerHTML = '';

  localSanitizedFiles.forEach((file, idx) => {
    const card = document.createElement('div');
    card.className = 'batch-item-card';

    // Preview element
    const previewBox = document.createElement('div');
    previewBox.className = 'batch-item-preview';

    if (file.previewMode === 'thumbnail' && file.thumbnailDataUrl) {
      const img = document.createElement('img');
      img.src = file.thumbnailDataUrl;
      previewBox.appendChild(img);
    } else if (file.blurhash) {
      const canvas = document.createElement('canvas');
      renderBlurhashCanvas(canvas, file.blurhash);
      previewBox.appendChild(canvas);
    } else {
      const badge = document.createElement('span');
      badge.textContent = file.mime.startsWith('audio/') ? '🎵' : '📄';
      badge.style.fontSize = '1.25rem';
      previewBox.appendChild(badge);
    }

    // Info element
    const infoBox = document.createElement('div');
    infoBox.className = 'batch-item-info';
    infoBox.innerHTML = `
      <div class="batch-item-name" title="${file.originalName || file.extension}">${file.originalName || `File ${idx + 1}`}</div>
      <div class="batch-item-meta">${formatBytes(file.cleanBytes.length)} · ${file.mime}</div>
    `;

    // Actions element
    const actionsBox = document.createElement('div');
    actionsBox.className = 'batch-item-actions';

    const isImageOrVideo = file.mime.startsWith('image/') || file.mime.startsWith('video/');
    if (isImageOrVideo) {
      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = `toggle-preview-btn ${file.previewMode === 'thumbnail' ? 'active' : ''}`;
      toggleBtn.innerHTML = file.previewMode === 'thumbnail' ? '👁️ Chiara' : '🔒 Sfocata';

      const hintText = document.createElement('span');
      hintText.className = 'toggle-preview-hint';
      if (file.thumbnailFallbackNotice) {
        hintText.textContent = 'Anteprima sfocata (> 8 KB)';
      } else {
        hintText.textContent = "Visibile prima dell'accordo";
      }

      toggleBtn.onclick = async () => {
        const rawFile = localRawFiles.get(file.id!);
        if (!rawFile) return;

        const newMode = file.previewMode === 'thumbnail' ? 'blurhash' : 'thumbnail';
        const updated = await sanitizeMediaFile(rawFile, newMode);
        updated.id = file.id;
        localSanitizedFiles[idx] = updated;
        renderLocalBatchList();
      };

      actionsBox.appendChild(toggleBtn);
      actionsBox.appendChild(hintText);
    }

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn-remove-item';
    removeBtn.innerHTML = '✕';
    removeBtn.title = 'Rimuovi file';
    removeBtn.onclick = () => {
      localRawFiles.delete(file.id!);
      localSanitizedFiles.splice(idx, 1);
      renderLocalBatchList();
    };
    actionsBox.appendChild(removeBtn);

    card.appendChild(previewBox);
    card.appendChild(infoBox);
    card.appendChild(actionsBox);
    listEl.appendChild(card);
  });
}

function sendLocalBatchOffer() {
  if (localSanitizedFiles.length === 0) {
    alert('Aggiungi almeno un file per inviare l offerta.');
    return;
  }

  const items = localSanitizedFiles.map((f) => ({
    cleanBytes: f.cleanBytes,
    mime: f.mime,
    previewMode: f.previewMode,
    blurhash: f.blurhash,
    thumbnailDataUrl: f.thumbnailDataUrl,
    declaredMax: f.declaredMax
  }));

  try {
    transferProto?.prepareAndSendBatchOffer(items);
    const sendBtn = document.getElementById('btn-send-offer') as HTMLButtonElement;
    if (sendBtn) {
      sendBtn.disabled = true;
      sendBtn.textContent = '✓ Offerta Inviata';
    }
  } catch (err: any) {
    alert(err.message);
  }
}

function renderRemoteOfferGrid() {
  const section = document.getElementById('remote-batch-section');
  const countEl = document.getElementById('remote-files-count');
  const totalSizeEl = document.getElementById('remote-batch-total-size');
  const gridEl = document.getElementById('remote-batch-grid');
  const mobCount = document.getElementById('mobile-remote-count');

  if (mobCount) mobCount.textContent = String(remoteOfferItems.length);
  if (!section || !countEl || !totalSizeEl || !gridEl) return;

  section.style.display = 'flex';
  countEl.textContent = String(remoteOfferItems.length);
  const totalDeclared = remoteOfferItems.reduce((acc, it) => acc + it.declaredMax, 0);
  totalSizeEl.textContent = `Tetto max: ${formatBytes(totalDeclared)}`;

  gridEl.innerHTML = '';

  if (remoteOfferItems.length === 0) {
    gridEl.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 24px 12px; text-align: center; color: var(--text-muted); font-size: 0.8rem; border: 1px dashed var(--border-color); border-radius: var(--radius);">
        In attesa che il peer selezioni e invii l'offerta dei suoi file...
      </div>
    `;
    return;
  }

  remoteOfferItems.forEach((item, idx) => {
    const card = document.createElement('div');
    card.className = 'remote-card';

    const previewBox = document.createElement('div');
    previewBox.className = 'remote-preview-box';

    // RIGID RECEIVER SECURITY: Assign thumbnails ONLY to img.src, NEVER innerHTML
    if (item.previewMode === 'thumbnail' && item.thumbnailDataUrl) {
      const img = document.createElement('img');
      img.src = item.thumbnailDataUrl;
      previewBox.appendChild(img);
    } else if (item.blurhash) {
      const canvas = document.createElement('canvas');
      renderBlurhashCanvas(canvas, item.blurhash);
      previewBox.appendChild(canvas);
    } else {
      const badge = document.createElement('span');
      badge.textContent = item.mime.startsWith('audio/') ? '🎵' : '📄';
      badge.style.fontSize = '1.5rem';
      previewBox.appendChild(badge);
    }

    const badgeLabel = item.previewMode === 'thumbnail' ? '👁️ Chiara' : '🔒 Sfocata';

    card.innerHTML = `
      <div class="text-sm" style="font-weight: 600; color: var(--text-primary);">File ${idx + 1}</div>
      <div class="badge ${item.previewMode === 'thumbnail' ? 'badge-direct' : ''}" style="font-size: 0.7rem; padding: 2px 6px;">${badgeLabel}</div>
      <div class="text-sm" style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">
        ${formatBytes(item.declaredMax)}<br/>${item.mime}
      </div>
    `;

    card.insertBefore(previewBox, card.firstChild);
    gridEl.appendChild(card);
  });
}

function renderBlurhashCanvas(canvas: HTMLCanvasElement, blurhashStr: string) {
  const w = 64;
  const h = 48;
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  try {
    const pixels = decodeBlurhash(blurhashStr, w, h);
    const imgData = ctx.createImageData(w, h);
    imgData.data.set(pixels);
    ctx.putImageData(imgData, 0, 0);
  } catch {}
}

function updateProgressBar(prog: TransferProgress) {
  const progressSec = document.getElementById('progress-section');
  if (progressSec) progressSec.style.display = 'flex';

  const sendPct = prog.totalToSend > 0 ? Math.min(100, Math.round((prog.bytesSent / prog.totalToSend) * 100)) : 0;
  const recvPct = prog.totalToReceive > 0 ? Math.min(100, Math.round((prog.bytesReceived / prog.totalToReceive) * 100)) : 0;

  const sendBar = document.getElementById('send-progress-bar');
  const sendTxt = document.getElementById('send-progress-pct');
  if (sendBar && sendTxt) {
    sendBar.style.width = `${sendPct}%`;
    sendTxt.textContent = `${sendPct}% (${formatBytes(prog.bytesSent)} / ${formatBytes(prog.totalToSend)})`;
  }

  const recvBar = document.getElementById('recv-progress-bar');
  const recvTxt = document.getElementById('recv-progress-pct');
  if (recvBar && recvTxt) {
    recvBar.style.width = `${recvPct}%`;
    recvTxt.textContent = `${recvPct}% (${formatBytes(prog.bytesReceived)})`;
  }
}

function renderWaitingReciprocalScreen() {
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card">
      <div class="reciprocal-wait-box">
        <div class="pulse" style="width: 32px; height: 32px; border-radius: 50%; background: var(--primary); box-shadow: 0 0 16px rgba(99, 102, 241, 0.6);"></div>
        <div class="terminal-sub">>_ RECIPROCAL LOCK GATE</div>
        <div class="card-title" style="margin-top: 4px;">Ricezione completata. In attesa del peer...</div>
        <div class="reciprocal-wait-warning">
          Se la connessione cade adesso, nessuno dei due terrà i file.
        </div>
        <p class="text-sm">
          Questo cancello reciproco riduce l'asimmetria tra i due utenti nel caso di client non manomessi.
          I tuoi file ricevuti sono custoditi in memoria e verranno sbloccati simultaneamente non appena anche la controparte confermerà la ricezione integrale.
        </p>
      </div>
    </div>
  `;
  bindHeaderEvents();
}

function renderCompletedScreen(completedFiles: CompletedFile[]) {
  const blobUrls: string[] = [];
  const totalBytes = completedFiles.reduce((acc, f) => acc + f.size, 0);

  const itemsHtml = completedFiles
    .map((file) => {
      const blobUrl = URL.createObjectURL(file.blob);
      blobUrls.push(blobUrl);

      let mediaEl = '';
      if (file.mime.startsWith('image/')) {
        mediaEl = `<img src="${blobUrl}" class="gallery-media-preview" />`;
      } else if (file.mime.startsWith('video/')) {
        mediaEl = `<video controls src="${blobUrl}" class="gallery-media-preview"></video>`;
      } else if (file.mime.startsWith('audio/')) {
        mediaEl = `<audio controls src="${blobUrl}" style="width: 100%; margin-top: 8px;"></audio>`;
      }

      return `
        <div class="gallery-card">
          ${mediaEl}
          <div class="text-sm" style="font-family: var(--font-mono); text-align: center; width: 100%;">
            <strong style="color: var(--text-primary); font-size: 0.88rem; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${file.name}</strong>
            <span style="color: var(--text-muted); font-size: 0.72rem;">${formatBytes(file.size)} · ${file.mime}</span>
          </div>
          <a href="${blobUrl}" download="${file.name}" class="btn btn-secondary btn-block" style="min-height: 42px;">
            Scarica File
          </a>
        </div>
      `;
    })
    .join('');

  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card">
      <div style="text-align: center; display: flex; flex-direction: column; gap: 8px; align-items: center;">
        <div class="badge badge-success">✓ Ricezione Conclusa & Verificata</div>
        <div class="card-title">File Ricevuti (${completedFiles.length})</div>
        <div class="text-sm" style="font-family: var(--font-mono); color: var(--ice-cyan); font-size: 0.8rem;">
          Totale trasferito: ${formatBytes(totalBytes)} · Integrità SHA-256 verificata
        </div>
      </div>

      <div class="gallery-grid">
        ${itemsHtml}
      </div>

      <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 8px;">
        <button id="btn-download-all" class="btn btn-primary btn-block" style="min-height: 48px;">
          <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
          Scarica Tutti i File (${completedFiles.length})
        </button>
        <span class="text-sm" style="text-align: center; color: var(--text-muted); font-size: 0.78rem;">
          Se il browser richiede l'autorizzazione per download multipli, seleziona 'Consenti'.
        </span>
      </div>

      <button id="btn-done" class="btn btn-secondary btn-block">Nuovo Scambio</button>
    </div>
  `;

  bindHeaderEvents();

  document.getElementById('btn-download-all')!.onclick = () => {
    completedFiles.forEach((file, idx) => {
      setTimeout(() => {
        const a = document.createElement('a');
        const url = URL.createObjectURL(file.blob);
        a.href = url;
        a.download = file.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 10000);
      }, idx * 200);
    });
  };

  document.getElementById('btn-done')!.onclick = () => {
    blobUrls.forEach((url) => URL.revokeObjectURL(url));
    resetToHome();
  };
}

function resetToHome() {
  if (sasTimerInterval) {
    clearInterval(sasTimerInterval);
    sasTimerInterval = null;
  }
  webrtcConn?.close();
  postTransport?.close();
  handshakeManager?.cleanup();
  pool?.close();

  webrtcConn = null;
  postTransport = null;
  handshakeManager = null;
  pool = null;
  identity = null;
  noiseSession = null;
  localRawFiles.clear();
  localSanitizedFiles = [];
  remoteOfferItems = [];

  renderHomeScreen();
}

// Router init
const route = checkRoute();
if (route.isTorMode) {
  renderTorStaticScreen();
} else if (route.directSecret) {
  startRoomSession(route.directSecret, true);
} else {
  renderHomeScreen();
}
