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

// PWA Service Worker Registration
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

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
  return `
    <header>
      <div class="logo-title">
        <svg class="logo-icon" viewBox="0 0 512 512" fill="none">
          <circle cx="256" cy="256" r="220" stroke="#00f2fe" stroke-width="24" stroke-dasharray="24 24"/>
          <path d="M256 140 V256 L340 340" stroke="#4facfe" stroke-width="28" stroke-linecap="round"/>
          <circle cx="256" cy="256" r="36" fill="#00f2fe"/>
        </svg>
        <span>AnonShare</span>
      </div>
      <div class="badge badge-direct">⚡ Modalità Diretta (WebRTC P2P)</div>
    </header>
  `;
}

/**
 * Section 2: Rigorous static Tor link screen with ZERO network activity.
 */
function renderTorStaticScreen() {
  appEl.innerHTML = `
    <header>
      <div class="logo-title">
        <svg class="logo-icon" viewBox="0 0 512 512" fill="none">
          <circle cx="256" cy="256" r="220" stroke="#c084fc" stroke-width="24"/>
          <circle cx="256" cy="256" r="36" fill="#c084fc"/>
        </svg>
        <span>AnonShare</span>
      </div>
      <div class="badge badge-tor">🧅 Modalità Tor</div>
    </header>

    <div class="card" style="text-align: center;">
      <div class="card-title">Modalità Tor Richiesta</div>
      <div class="alert-info" style="font-size: 1rem; padding: 1.25rem;">
        Questo scambio richiede l'app Android in modalità Tor.<br/>
        Apri il link sull'app <strong>AnonShare</strong>.
      </div>
      <p class="text-sm">
        La versione Web non esegue Tor onion services per preservare il massimo anonimato. Nessuna connessione di rete è stata aperta dal tuo browser.
      </p>
      <a href="/" class="btn btn-secondary btn-block">Torna alla Modalità Diretta</a>
    </div>
  `;
}

function renderHomeScreen() {
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card">
      <div class="card-title">Scambio Bilaterale Riservato P2P</div>
      <p class="text-sm">
        Scambia file multimediali direttamente tra due browser, senza server di archiviazione, con sanificazione automatica dei metadati, cifratura Noise NNpsk0 e anteprime selettive.
      </p>

      <div class="alert-warning">
        <strong>Avviso sulla Privacy di Rete:</strong> In Modalità Diretta, WebRTC connette direttamente i due partecipanti. I peer e i relay Nostr vedono gli indirizzi IP. Per proteggere il tuo indirizzo IP, usa una VPN a livello di sistema operativo.
      </div>

      <button id="btn-create-room" class="btn btn-primary btn-block">
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 4v16m8-8H4"></path></svg>
        Crea Nuova Stanza
      </button>

      <div style="text-align: center; color: var(--text-muted); font-size: 0.85rem;">oppure partecipa con un link</div>

      <div class="input-group">
        <input type="text" id="input-join-link" placeholder="Incolla link o segreto..." />
        <button id="btn-join-room" class="btn btn-secondary">Entra</button>
      </div>
    </div>
  `;

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
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card">
      <div class="card-title">Stanza Creata — In Attesa del Partecipante</div>
      <p class="text-sm">
        Condividi questo link temporaneo monouso con la persona con cui desideri scambiare i file:
      </p>

      <div class="input-group">
        <input type="text" readonly value="${roomUrl}" id="room-url-input" />
        <button class="btn btn-secondary" id="btn-copy-url">Copia</button>
      </div>

      <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: var(--radius-md);">
        <div class="pulse" style="width: 12px; height: 12px; border-radius: 50%; background: var(--accent-cyan);"></div>
        <span class="text-sm" id="handshake-status-text">In ascolto sui relay Nostr pubblici...</span>
      </div>

      <div class="text-sm" style="font-family: var(--font-mono); font-size: 0.75rem; opacity: 0.7;">
        Room Tag: ${roomTag.substring(0, 16)}...
      </div>

      <button id="btn-cancel-session" class="btn btn-danger btn-block">Annulla Stanza</button>
    </div>
  `;

  document.getElementById('btn-copy-url')!.onclick = () => {
    navigator.clipboard.writeText(roomUrl);
    const btn = document.getElementById('btn-copy-url')!;
    btn.textContent = 'Copiato!';
    setTimeout(() => (btn.textContent = 'Copia'), 2000);
  };

  document.getElementById('btn-cancel-session')!.onclick = () => {
    resetToHome();
  };
}

function renderInitiatingScreen() {
  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card" style="text-align: center;">
      <div class="card-title">Connessione alla Stanza...</div>
      <div style="display: flex; justify-content: center; margin: 1.5rem 0;">
        <div class="pulse" style="width: 24px; height: 24px; border-radius: 50%; background: var(--accent-cyan);"></div>
      </div>
      <p class="text-sm" id="handshake-status-text">
        Invio richiesta di handshake cifrato Noise NNpsk0...
      </p>
      <button id="btn-cancel-session" class="btn btn-danger btn-block" style="margin-top: 1rem;">Annulla</button>
    </div>
  `;

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
      <div class="card-title" style="color: var(--accent-cyan);">Verifica di Sicurezza SAS</div>
      
      <div class="alert-warning">
        <strong>Confronto Vocale Fuori Banda:</strong> Confronta queste 6 parole con il tuo interlocutore su un canale diverso da quello in cui hai condiviso il link (a voce o in chiamata).
      </div>

      <div class="sas-grid">
        ${sasWords
          .map(
            (word, idx) => `
          <div class="sas-word-box">
            <span class="sas-word-num">Parola ${idx + 1}</span>
            <span class="sas-word-val">${word}</span>
          </div>
        `
          )
          .join('')}
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;" class="text-sm">
        <span>Tempo rimasto per la verifica:</span>
        <strong id="sas-timer" style="color: var(--accent-amber); font-family: var(--font-mono);">5:00</strong>
      </div>

      <div style="display: flex; gap: 0.75rem;">
        <button id="btn-confirm-sas" class="btn btn-success" style="flex: 2;">
          ✓ Confermo Corrispondenza
        </button>
        <button id="btn-cancel-sas" class="btn btn-danger" style="flex: 1;">
          ✕ Annulla
        </button>
      </div>

      <p class="text-sm" id="webrtc-state-text" style="text-align: center; color: var(--text-muted); margin-top: 0.5rem;">
        In attesa della tua conferma...
      </p>
    </div>
  `;

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

    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span class="card-title">Scambio Diretto P2P Multi-Media</span>
        <span class="badge badge-success">Connesso E2EE</span>
      </div>

      <!-- File Dropzone -->
      <div id="file-dropzone" class="dropzone">
        <svg width="40" height="40" fill="none" stroke="#00f2fe" stroke-width="1.5" viewBox="0 0 24 24">
          <path d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
        </svg>
        <div>
          <strong>Trascina file qui</strong> o clicca per selezionare
          <div class="text-sm" style="margin-top: 0.3rem;">Fino a 50 file (JPEG, PNG, WebP, MP4, WebM, MP3, FLAC - Max 100 MB totali)</div>
        </div>
        <input type="file" id="file-input" multiple style="display: none;" accept="image/*,video/mp4,video/webm,audio/mpeg,audio/flac" />
      </div>

      <div id="sanitizing-indicator" style="display: none;" class="alert-info">
        <div class="pulse">Sanificazione metadati in corso (bonifica EXIF, GPS e rigenerazione canvas)...</div>
      </div>

      <!-- Local Selection List -->
      <div id="local-batch-section" style="display: none; flex-direction: column; gap: 0.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 0.95rem;">I Tuoi File (<span id="local-files-count">0</span>)</strong>
          <span id="local-batch-total-size" class="text-sm" style="font-family: var(--font-mono);">0 B / 100 MB</span>
        </div>
        <div id="local-batch-list" class="batch-list"></div>
        <button id="btn-send-offer" class="btn btn-primary btn-block">Invia Offerta Batch al Peer</button>
      </div>

      <!-- Remote Offer Section -->
      <div id="remote-batch-section" style="display: none; flex-direction: column; gap: 0.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 0.95rem;">File Proposti dal Peer (<span id="remote-files-count">0</span>)</strong>
          <span id="remote-batch-total-size" class="text-sm" style="font-family: var(--font-mono);"></span>
        </div>
        <div id="remote-batch-grid" class="remote-grid"></div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.5rem;">
        <button id="btn-accept-exchange" class="btn btn-success btn-block" disabled>
          In attesa dello scambio delle offerte...
        </button>
        <span id="transfer-status-text" class="text-sm" style="text-align: center;">
          Seleziona uno o più file per avviare lo scambio.
        </span>
      </div>

      <!-- Progress Section -->
      <div id="progress-section" style="display: none; flex-direction: column; gap: 0.75rem;">
        <div class="progress-container">
          <div style="display: flex; justify-content: space-between;" class="text-sm">
            <span>Invio Dati Cifrati</span>
            <span id="send-progress-pct">0%</span>
          </div>
          <div class="progress-bar-bg"><div id="send-progress-bar" class="progress-bar-fill" style="width: 0%;"></div></div>
        </div>

        <div class="progress-container">
          <div style="display: flex; justify-content: space-between;" class="text-sm">
            <span>Ricezione Dati Cifrati</span>
            <span id="recv-progress-pct">0%</span>
          </div>
          <div class="progress-bar-bg"><div id="recv-progress-bar" class="progress-bar-fill" style="width: 0%;"></div></div>
        </div>
      </div>
    </div>
  `;

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

  if (!section || !countEl || !totalSizeEl || !listEl) return;

  if (localSanitizedFiles.length === 0) {
    section.style.display = 'none';
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
      toggleBtn.className = `toggle-preview-btn ${file.previewMode === 'thumbnail' ? 'active' : ''}`;
      toggleBtn.innerHTML = file.previewMode === 'thumbnail' ? '👁️ Miniatura Chiara' : '🔒 Sfocata (BlurHash)';

      const hintText = document.createElement('span');
      hintText.className = 'toggle-preview-hint';
      if (file.thumbnailFallbackNotice) {
        hintText.textContent = 'Miniatura troppo complessa (> 8 KB): impostata anteprima sfocata standard';
      } else {
        hintText.textContent = "L'altra persona vedrà questa immagine prima di accettare lo scambio";
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

  if (!section || !countEl || !totalSizeEl || !gridEl) return;

  section.style.display = 'flex';
  countEl.textContent = String(remoteOfferItems.length);
  const totalDeclared = remoteOfferItems.reduce((acc, it) => acc + it.declaredMax, 0);
  totalSizeEl.textContent = `Tetto max dichiarato: ${formatBytes(totalDeclared)}`;

  gridEl.innerHTML = '';

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
      <div class="text-sm" style="font-weight: 600;">File ${idx + 1}</div>
      <div class="badge ${item.previewMode === 'thumbnail' ? 'badge-direct' : ''}" style="font-size: 0.72rem;">${badgeLabel}</div>
      <div class="text-sm" style="font-size: 0.75rem; color: var(--text-muted);">
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
        <div class="pulse" style="width: 32px; height: 32px; border-radius: 50%; background: var(--accent-cyan);"></div>
        <div class="card-title">Ricezione completata. In attesa del completamento del peer...</div>
        <div class="reciprocal-wait-warning">
          Se la connessione cade adesso, nessuno dei due terrà i file.
        </div>
        <p class="text-sm">
          Questo cancello reciproco riduce l'asimmetria tra i due utenti nel caso di client non manomessi; non è un meccanismo atomico.
          I tuoi file ricevuti sono custoditi in memoria e verranno sbloccati simultaneamente non appena anche la controparte avrà confermato la ricezione integrale.
        </p>
      </div>
    </div>
  `;
}

function renderCompletedScreen(completedFiles: CompletedFile[]) {
  const blobUrls: string[] = [];

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
        mediaEl = `<audio controls src="${blobUrl}" style="width: 100%;"></audio>`;
      }

      return `
        <div class="gallery-card">
          ${mediaEl}
          <div class="text-sm" style="font-family: var(--font-mono); text-align: center;">
            <strong>${file.name}</strong><br/>
            ${formatBytes(file.size)} · ${file.mime}
          </div>
          <a href="${blobUrl}" download="${file.name}" class="btn btn-secondary btn-block">
            Scarica File
          </a>
        </div>
      `;
    })
    .join('');

  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card">
      <div style="text-align: center; display: flex; flex-direction: column; gap: 0.5rem; align-items: center;">
        <div class="badge badge-success">✓ Scambio Concluso con Successo</div>
        <div class="card-title">File Ricevuti e Verificati (${completedFiles.length})</div>
      </div>

      <div class="gallery-grid">
        ${itemsHtml}
      </div>

      <div style="display: flex; flex-direction: column; gap: 0.5rem; margin-top: 1rem;">
        <button id="btn-download-all" class="btn btn-primary btn-block">
          <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
          Scarica Tutti i File (${completedFiles.length})
        </button>
        <span class="text-sm" style="text-align: center; color: var(--text-muted); font-size: 0.8rem;">
          Nota: se il browser richiede l'autorizzazione per scaricare più file contemporaneamente, seleziona 'Consenti'.
        </span>
      </div>

      <button id="btn-done" class="btn btn-secondary btn-block">Chiudi Sessione</button>
    </div>
  `;

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
