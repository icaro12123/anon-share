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
  FileOffer,
  CompletedFile,
  TransferProgress
} from './protocol/transfer.ts';
import { formatBytes } from './media/magic.ts';

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
    // 1. Remove fragment immediately from history and URL bar
    window.history.replaceState(null, '', '/t/');
    return { isTorMode: true, directSecret: null };
  }

  // Direct Mode link: #direct&secret=<hex>
  if (hash.includes('secret=')) {
    const params = new URLSearchParams(hash.replace(/^#/, ''));
    const secretHex = params.get('secret');
    // Clear fragment immediately from URL
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

let localSanitizedFile: SanitizedMedia | null = null;
let remoteFileOffer: FileOffer | null = null;
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
        Scambia file multimediali direttamente tra due browser, senza server di archiviazione, con sanificazione automatica dei metadati e cifratura Noise NNpsk0.
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
    // Alice waiting screen
    renderWaitingScreen(roomUrl, roomTag);
  } else {
    // Bob connecting screen
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
        Condividi questo link temporaneo monouso con la persona con cui desideri scambiare il file:
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

/**
 * Triggered when Noise NNpsk0 handshake finishes successfully.
 * Enters Section 3.4 Blocking SAS Gate.
 */
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

/**
 * WebRTC DataChannel is ready and Nostr has been cleanly shut down.
 * Entering Section 5: The 3-Stage Exchange.
 */
function onDataChannelEstablished(isInitiator: boolean) {
  if (sasTimerInterval) clearInterval(sasTimerInterval);

  transferProto = new TransferProtocol({
    isInitiator,
    noiseSession: noiseSession!,
    sendRawData: (data) => webrtcConn?.sendData(data),
    onOfferReceived: (offer) => {
      remoteFileOffer = offer;
      updateTeaserDisplay();
    },
    onStateChange: (state, msg) => {
      const stateEl = document.getElementById('transfer-status-text');
      if (stateEl && msg) stateEl.textContent = msg;

      if (state === 'both_offered') {
        const acceptBtn = document.getElementById('btn-accept-exchange') as HTMLButtonElement;
        if (acceptBtn) acceptBtn.disabled = false;
      }
    },
    onProgress: (prog) => {
      updateProgressBar(prog);
    },
    onFileCompleted: (completed) => {
      renderCompletedScreen(completed);
    },
    onError: (err) => {
      alert(`Errore scambio: ${err}`);
      resetToHome();
    }
  });

  // Connect incoming WebRTC DataChannel messages to the TransferProtocol!
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
        <span class="card-title">Scambio Diretto P2P</span>
        <span class="badge badge-success">Connesso E2EE</span>
      </div>

      <!-- File Dropzone -->
      <div id="file-dropzone" class="dropzone">
        <svg width="40" height="40" fill="none" stroke="#00f2fe" stroke-width="1.5" viewBox="0 0 24 24">
          <path d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
        </svg>
        <div>
          <strong>Trascina un file qui</strong> o clicca per selezionare
          <div class="text-sm" style="margin-top: 0.3rem;">JPEG, PNG, WebP, MP4, WebM, MP3, FLAC (Max 100 MB)</div>
        </div>
        <input type="file" id="file-input" style="display: none;" accept="image/*,video/mp4,video/webm,audio/mpeg,audio/flac" />
      </div>

      <div id="sanitizing-indicator" style="display: none;" class="alert-info">
        <div class="pulse">Sanificazione metadati in corso (eliminazione EXIF, GPS e rigenerazione canvas)...</div>
      </div>

      <!-- Teaser Row (Section 5 Stage 1) -->
      <div class="teaser-row">
        <div class="teaser-box">
          <strong style="font-size: 0.9rem;">Il Tuo File</strong>
          <canvas id="my-teaser-canvas" class="teaser-canvas"></canvas>
          <div id="my-file-info" class="text-sm">Nessun file selezionato</div>
        </div>

        <div class="teaser-box">
          <strong style="font-size: 0.9rem;">File del Peer</strong>
          <canvas id="peer-teaser-canvas" class="teaser-canvas"></canvas>
          <div id="peer-file-info" class="text-sm">In attesa del file del peer...</div>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 0.5rem;">
        <button id="btn-accept-exchange" class="btn btn-success btn-block" disabled>
          Accetta Scambio Bilaterale
        </button>
        <span id="transfer-status-text" class="text-sm" style="text-align: center;">
          Seleziona un file per iniziare lo scambio.
        </span>
      </div>

      <!-- Progress Section (Stage 3) -->
      <div id="progress-section" style="display: none; flex-direction: column; gap: 0.75rem;">
        <div class="progress-container">
          <div style="display: flex; justify-content: space-between;" class="text-sm">
            <span>Invio Chunk Noise</span>
            <span id="send-progress-pct">0%</span>
          </div>
          <div class="progress-bar-bg"><div id="send-progress-bar" class="progress-bar-fill" style="width: 0%;"></div></div>
        </div>

        <div class="progress-container">
          <div style="display: flex; justify-content: space-between;" class="text-sm">
            <span>Ricezione Chunk Noise</span>
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
    if (fileInput.files?.[0]) {
      await handleFileSelection(fileInput.files[0]);
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
    if (e.dataTransfer?.files?.[0]) {
      await handleFileSelection(e.dataTransfer.files[0]);
    }
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

async function handleFileSelection(file: File) {
  const sanitizeInd = document.getElementById('sanitizing-indicator');
  if (sanitizeInd) sanitizeInd.style.display = 'block';

  try {
    localSanitizedFile = await sanitizeMediaFile(file);
    if (sanitizeInd) sanitizeInd.style.display = 'none';

    // Update local teaser UI
    const myInfo = document.getElementById('my-file-info');
    if (myInfo) {
      myInfo.textContent = `${formatBytes(localSanitizedFile.cleanBytes.length)} (${localSanitizedFile.mime})`;
    }

    if (localSanitizedFile.blurhash) {
      drawBlurhashToCanvas('my-teaser-canvas', localSanitizedFile.blurhash);
    } else {
      drawPlaceholderToCanvas('my-teaser-canvas', localSanitizedFile.mime);
    }

    // Send Offer via Noise DataChannel
    transferProto?.prepareAndSendOffer({
      cleanBytes: localSanitizedFile.cleanBytes,
      mime: localSanitizedFile.mime,
      extension: localSanitizedFile.extension,
      blurhash: localSanitizedFile.blurhash,
      declaredMax: localSanitizedFile.declaredMax
    });
  } catch (err: any) {
    if (sanitizeInd) sanitizeInd.style.display = 'none';
    alert(`Errore file: ${err.message}`);
  }
}

function updateTeaserDisplay() {
  if (!remoteFileOffer) return;

  const peerInfo = document.getElementById('peer-file-info');
  if (peerInfo) {
    peerInfo.textContent = `Tetto: ${formatBytes(remoteFileOffer.declaredMax)} (${remoteFileOffer.mime})`;
  }

  if (remoteFileOffer.blurhash) {
    drawBlurhashToCanvas('peer-teaser-canvas', remoteFileOffer.blurhash);
  } else {
    drawPlaceholderToCanvas('peer-teaser-canvas', remoteFileOffer.mime);
  }
}

function drawPlaceholderToCanvas(canvasId: string, mime: string) {
  const canvas = document.getElementById(canvasId) as HTMLCanvasElement;
  if (!canvas) return;
  canvas.width = 128;
  canvas.height = 96;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#38bdf8';
  ctx.font = 'bold 14px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const label = mime.startsWith('video/') ? '🎬 Video' : mime.startsWith('audio/') ? '🎵 Audio' : '📄 File';
  ctx.fillText(label, canvas.width / 2, canvas.height / 2);
}

function drawBlurhashToCanvas(canvasId: string, blurhashStr: string) {
  const canvas = document.getElementById(canvasId) as HTMLCanvasElement;
  if (!canvas) return;

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
    sendTxt.textContent = `${sendPct}% (${formatBytes(prog.bytesSent)})`;
  }

  const recvBar = document.getElementById('recv-progress-bar');
  const recvTxt = document.getElementById('recv-progress-pct');
  if (recvBar && recvTxt) {
    recvBar.style.width = `${recvPct}%`;
    recvTxt.textContent = `${recvPct}% (${formatBytes(prog.bytesReceived)})`;
  }
}

function renderCompletedScreen(completed: CompletedFile) {
  const blobUrl = URL.createObjectURL(completed.blob);

  // Render sandboxed iframe preview per Section 8
  let previewHtml = '';
  if (completed.mime.startsWith('image/')) {
    previewHtml = `<img src="${blobUrl}" style="max-width: 100%; max-height: 350px; border-radius: var(--radius-md); object-fit: contain;" />`;
  } else if (completed.mime.startsWith('video/')) {
    previewHtml = `<video controls src="${blobUrl}" style="max-width: 100%; max-height: 350px; border-radius: var(--radius-md);"></video>`;
  } else if (completed.mime.startsWith('audio/')) {
    previewHtml = `<audio controls src="${blobUrl}" style="width: 100%;"></audio>`;
  }

  appEl.innerHTML = `
    ${renderHeader()}

    <div class="card" style="text-align: center;">
      <div class="badge badge-success" style="align-self: center;">✓ Scambio Concluso con Successo</div>
      <div class="card-title">File Ricevuto e Verificato</div>

      <div style="background: rgba(0,0,0,0.3); padding: 1.25rem; border-radius: var(--radius-md); display: flex; flex-direction: column; align-items: center; gap: 1rem;">
        ${previewHtml}
        <div class="text-sm" style="font-family: var(--font-mono);">
          <strong>${completed.name}</strong><br/>
          ${formatBytes(completed.size)} · ${completed.mime}
        </div>
      </div>

      <a href="${blobUrl}" download="${completed.name}" class="btn btn-primary btn-block">
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
        Scarica File Sanificato
      </a>

      <button id="btn-done" class="btn btn-secondary btn-block">Chiudi Sessione</button>
    </div>
  `;

  document.getElementById('btn-done')!.onclick = () => {
    URL.revokeObjectURL(blobUrl);
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
  localSanitizedFile = null;
  remoteFileOffer = null;

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
