# Piano Architetturale v9.4: AnonShare — Zero-Server, Zero-Cost P2P & Tor Transport

## Changelog
### v9.3 -> v9.4
* Estensione al trasferimento multi-media (batch fino a 50 file e 100 MB complessivi); offerta multi-messaggio (`OFFER_ITEM` per file e `OFFER_END`) compliant con i frame Noise da 65535 byte; anteprime selettive per file con Miniatura Chiara permissiva (JPEG <= 8 KB su canvas bonificato, fallback trasparente a BlurHash); doppio consenso batch su array di commitment SHA-256 e `BATCH_SALTS` come array indicizzato posizionalmente (`salts[i]`); streaming rigoroso con tetto byte `declaredMax` per file, prefisso `fileIndex` nei chunk DATA e chiusura ordinata `FILE_START`/`FILE_END`; cancello di sblocco reciproco post-trasferimento (`BATCH_RECEIVE_COMPLETE`) con blocco file in RAM per ridurre l'asimmetria; validazione stringente lato ricevente (somma declaredMax, conteggio, prefisso data:image/jpeg;base64,, assegnazione esclusiva a `img.src`, estensione derivata unicamente da allowlist MIME ed esecuzione verifica magic bytes a fine ricezione); piano di test aggiornato con suite batch.
### v9.2 -> v9.3
* Ripristinato il flusso completo post-connessione in Sez. 4 (Modalità Tor) con client authorization, Noise NNpsk0, SAS bloccante e Fasi 1-3 su socket onion; formalizzato `declared_max` dal limite superiore dello scaglione con verifiche di arrivo `FILE_END`, `total_bytes == ricevuti` e hash (sez. 5, 8, 11); rinominata sez. 5 in "Doppio Consenso e Rilascio del Salt"; chiarito `seq` all'interno del plaintext del messaggio Noise (sez. 3.2b).
### v9.1 -> v9.2
* Cifratura unificata su Noise transport (rimozione totale di libsodium e `secretstream`); SAS a 66 bit (6 indici su wordlist 2048 parole) con timeout 5 min e gestione background/resubscribe; simmetria anti-DoS sull'handshake Nostr (stato candidato anche per Bob, scarto payload != 48B, scarto echo pubkey, protocollo Noise_NNpsk0_25519_ChaChaPoly_SHA256 con prologue); gestione messaggi post-handshake su Nostr (niente trickle ICE, seq all'interno del plaintext del messaggio Noise, deduplica e retry buffer); Modalità Tor migliorata (onion address nel fragment URL, chiusura Decisione Aperta 4 con client authorization v3 via HKDF, rate limit socket); gestione link Tor su Web con schermata statica e zero chiamate di rete; hosting Android App Links su github.io gratuito; piano di test aggiornato.
### v9 -> v9.1
* Risoluzione difetti macchina a stati handshake Nostr (anti-DoS su msg1 con validazione AEAD e HandshakeState usa-e-getta, cache e reinvio rate-limited di msg2, ripubblicazioni con eventi Nostr freschi) e formalizzazione crittografica rigorosa (SAS derivata da h, mappatura esplicita c1 Bob->Alice e c2 Alice->Bob).

---

## 1. Threat Model e Tabella delle Garanzie

### Ambito e Assunzioni
* **Target di Riferimento**: Utenti comuni e di medio livello tecnico che utilizzano l'applicazione Web ufficiale o l'APK compilato ufficiale.
* **Infrastruttura**: Zero server proprietari; impiego esclusivo di relay Nostr pubblici aperti e server STUN pubblici gratuiti (Google, Cloudflare) per la sola negoziazione diretta.
* **Attaccanti In-Scope**:
  1. *Utente remoto con app ufficiale non modificata*: Tenta di curiosare nei metadati o di effettuare correlazioni prima dell'accordo.
  2. *Operatori dei Relay Nostr Pubblici*: Possono loggare gli IP dei client connessi via WebSocket, gli orari e i `RoomTag` degli eventi pubblicati/sottoscritti; possono tentare DoS iniettando eventi spazzatura o tentare censura.
  3. *Server STUN Pubblici*: Registrano gli indirizzi IP pubblici e le porte dei client durante l'hole punching.
  4. *Osservatore di Rete Passivo (ISP / Wi-Fi pubblico)*: Ispeziona pacchetti, monitora indirizzi IP e query DNS.
* **Fuori Scope (Esclusioni Esplicite)**:
  * **Client o Versione Web Modificati**: Utenti che decompilano, alterano o ricompilano il client per violare il protocollo di scambio, interrompere la trasmissione a tradimento o inviare payload arbitrari.
  * Compromissione del dispositivo locale, malware, spyware, browser zero-day.
  * Attaccanti statali capaci di monitoraggio globale del traffico (attacchi di correlazione temporale su larga scala).

### Tabella delle Garanzie

| Proprietà / Promessa | Contro chi VALE | Contro chi NON VALE (Limiti Noti) | Note Tecniche |
| :--- | :--- | :--- | :--- |
| **Riservatezza Dati e Controllo (E2EE)** | ISP, osservatori di rete, operatori Nostr, server STUN. | Malware sul dispositivo locale; chi possiede il link attivo durante la sessione. | **Noise NNpsk0 (`c1`/`c2`) per controllo e dati**; nessun dato in chiaro sul canale. |
| **Perfect Forward Secrecy (PFS)** | Chi compromette il link $S_{\text{room}}$ in futuro (es. da chat log). | Chi intercetta il link in tempo reale durante l'handshake. | **Garantita dal DH effimero ($ee$) di Noise** su tutto il traffico post-handshake. |
| **Protezione del File da Dizionari** | Utente remoto, relay Nostr e osservatori (prima dell'accordo in Fase 2). | Non protegge il Teaser (il BlurHash è confrontabile se il file è già noto; la Miniatura Chiara mostra un'immagine riconoscibile). | Commitment $H_i(\text{salt}_i \mathbin{\Vert} \text{FilePulito}_i)$ con salt 256-bit inviato solo dopo il doppio consenso. |
| **Anteprime Selettive (Miniatura Chiara)** | Chi riceve l'anteprima (non ottiene il file originale né metadati EXIF/GPS). | L'altra persona vede un'immagine riconoscibile (micro-thumbnail 120x90, max 8 KB) **prima** del consenso di scambio. | Scelta esplicita per ciascun file con avviso in UI ("L'altra persona vedrà questa immagine prima di accettare lo scambio"). Fallback automatico a BlurHash se > 8 KB. |
| **Anti-Correlazione tra Sessioni** | Osservatori e operatori Nostr (sul contenuto). | **Senza VPN i relay vedono l'IP** e possono correlare le sessioni per IP; non nasconde la dimensione a scaglioni. | Canale Noise cifrato e salt casuale indipendente per ogni singolo file della sessione. |
| **Resistenza a DoS su Nostr** | Nodi relay malevoli o spammer sul `RoomTag`. | Se l'attaccante conosce il segreto $S_{\text{room}}$. | Verifica del tag AEAD (16 byte) su stato candidato effimero (sia Alice che Bob) prima del lock. |
| **Anonimato IP — Modalità Tor (Solo APK)** | Utente remoto, ISP locale, relay Nostr e server STUN (non utilizzati). | Attacchi avanzati di correlazione temporale su nodi Tor; reti con blocco di Tor. | Valido **solo** tra due APK con `arti`; onion service effimero v3 con client auth; zero WebRTC. |
| **Anonimato IP — Modalità Diretta (Web / APK)** | **NON GARANTITO**. I peer e i server di rete vedono gli IP. | L'altro utente vede il tuo IP; i relay Nostr e i server STUN vedono il tuo IP. | WebRTC P2P diretto; la UI avverte esplicitamente: *"usa una VPN a livello di sistema (non un'estensione browser)"*. |
| **Autenticità Handshake (Anti-MITM)** | Chiunque abbia intercettato il link nella chat di condivisione (i relay sono già bloccati dal PSK). | Se gli utenti saltano o confermano superficialmente il codice SAS a 6 parole. | Gate SAS bloccante a 6 parole (66 bit) derivato da $h$; confronto vocale fuori banda. |
| **Rimozione Metadati Immagini** | Chi riceve l'immagine (non può leggere GPS, modello fotocamera, timestamp). | Watermark visibili o steganografia integrata nei pixel stessi della foto. | Canvas Re-encoding (distrugge nativamente tutti i metadati non grafici). |
| **Equità dello Scambio (Cancello Reciproco)** | Peer che utilizzano l'applicazione ufficiale non modificata. | Utenti che utilizzano un client manomesso o chiudono il browser durante il download. | Il cancello di sblocco reciproco (`BATCH_RECEIVE_COMPLETE`) **riduce l'asimmetria tra i due utenti nel caso di client non manomessi; non è un meccanismo atomico**. |

---

## 2. Le Due Modalità di Trasferimento (Scelta alla Creazione)

La modalità viene selezionata all'atto della creazione della stanza ed è codificata in modo immutabile nel link:

```
                                [ Creazione Stanza ]
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
         [ Modalità Diretta ]                       [ Modalità Tor ]
        (Web Browser oppure APK)                  (Solo tra due APK nativi)
                    │                                         │
        Link: https://<host>/#direct&...          Link: https://<host>/t/#onion=...&secret=...
                    │                                         │
                    ▼                                         ▼
    Signaling: Pool Relay Nostr Pubblici       Rendezvous Nativo: Onion Service v3
    Eventi Effimeri (kind 20000-29999)         Alice ospita onion service con Client Auth
    Handshake: Noise NNpsk0 su Nostr           Bob si connette via circuito Tor
    Dati: WebRTC P2P Diretto (Noise c1/c2)     Dati: Socket TCP onion (Noise c1/c2)
    I peer e STUN vedono gli IP                IP schermati nei limiti di Tor
```

### Comportamento Rigido della Versione Web sui Link Tor
Se un utente incolla o apre un link Tor (`/t/#onion=...&secret=...`) nella versione Web del browser:
1. La Web App intercetta il prefisso `/t/` ed estrae i parametri dal fragment.
2. **Rimuove immediatamente il fragment dall'URL** con `history.replaceState(null, "", "/t/")` per non lasciare tracce nella cronologia o nella barra degli indirizzi.
3. Mostra **esclusivamente una schermata statica informativa**:
   > *"Questo scambio richiede l'app Android in modalità Tor. Apri il link sull'app AnonShare per scambiare il batch di file."*
4. **Zero Attività di Rete**: la Web App non effettua alcuna chiamata WebSocket verso i relay Nostr, non istanzia `RTCPeerConnection`, non invia richieste STUN e non effettua alcun fallback silenzioso alla Modalità Diretta (il link Tor non contiene un `RoomTag` utilizzabile per la modalità diretta e non deve mai essere convertito). Non viene loggato né memorizzato alcun dato.
5. Se l'APK Android è installato, l'Android App Link verificato intercetta l'URL e apre direttamente l'app nativa senza caricare la pagina web.

---

## 3. Modalità Diretta: Signaling su Nostr Pubblico e WebRTC Diretto

### 3.1 Igiene Crittografica e Derivazione Chiavi
All'apertura dell'applicazione, il creatore genera un segreto casuale a 256 bit $S_{\text{room}}$ tramite `crypto.getRandomValues(new Uint8Array(32))`. Tramite **HKDF** (Extract + Expand con SHA-256) si derivano con separazione di dominio:
1. **$\text{PSK}_{\text{Noise}}$** ($32 \text{ byte}$):
   $$\text{PSK}_{\text{Noise}} = \text{HKDF-Expand}(S_{\text{room}}, \text{"ANONSHARE-v1-NOISE-PSK"}, 32)$$
2. **$\text{RoomTag}$** ($32 \text{ byte}$, codificato in stringa esadecimale da 64 caratteri per il tag `#d` di Nostr):
   $$\text{RoomTag} = \text{HKDF-Expand}(S_{\text{room}}, \text{"ANONSHARE-v1-NOSTR-ROOM-TAG"}, 32)$$

Le coppie di chiavi Nostr sono usa-e-getta e generate in RAM per ogni sessione. Dopo aver letto il frammento URL nel browser, il client lo rimuove istantaneamente con `history.replaceState`.

### 3.2 Protocollo di Handshake Noise NNpsk0 su Nostr (Simmetria Anti-DoS)
Il protocollo adotta formalmente **`Noise_NNpsk0_25519_ChaChaPoly_SHA256`** con:
* `prologue = "ANONSHARE-v1-DIRECT"`
* `psk = PSK_Noise`
* Utilizzo di una libreria Noise collaudata (es. `snow` in Rust per l'APK e implementazione validata sui test vector ufficiali in TypeScript per il Web).

```
Alice (Creatore - Responder)                      Bob (Partecipante - Initiator)
         |                                                   |
         | <==== [ Sottoscrizione REQ su RoomTag ]           |
         |       (In ascolto passivo, TTL 15m)               |
         |                                                   | <==== [ Sottoscrizione REQ su RoomTag ]
         |                                                   |
         | <---- msg 1 (Nostr Event 1: e_B + AEAD Tag) ------|       (Pubblica msg 1, payload vuoto)
         |       [ Verifica AEAD su HandshakeState tmp ]      |       (Se non riceve msg 2:
         |       [ Tag valido => IN_SESSION + Cache msg 2 ]   |        ripubblica msg 1 ogni 3s
         |                                                   |        con timestamp Nostr NUOVO)
         | ----- msg 2 (Nostr Event: e_A, ee) -------------> |
         |                                                   | <==== [ Verifica AEAD su HandshakeState tmp ]
         |                                                   |       [ Tag valido => Commit + Stop Retry ]
   [ Split() => h, c2(Alice->Bob) ]                   [ Split() => h, c1(Bob->Alice) ]
```

#### Regole Rigide della Macchina a Stati:
1. **Filtro Preliminare Dimensioni ed Eco**:
   - Sia Alice che Bob scartano a monte qualsiasi evento firmato con la propria chiave pubblica Nostr effimera (filtro eco del relay).
   - Sia Alice che Bob scartano prima di qualunque operazione crittografica qualsiasi payload che non sia **esattamente di 48 byte** (32 byte chiave effimera X25519 + 16 byte auth tag Poly1305).
2. **Stato Candidato Effimero Anti-DoS (Sia Alice che Bob)**:
   - **Alice (Responder)**: all'arrivo di `msg 1`, alloca una `HandshakeState` candidata con $\text{PSK}_{\text{Noise}}$ ed esegue `ReadMessage`. Se il tag AEAD fallisce, il messaggio viene scartato silenziosamente e lo stato principale non viene alterato. Solo su autenticazione valida commuta in `IN_SESSION`.
   - **Bob (Initiator)**: all'arrivo di `msg 2`, alloca una copia temporanea della propria `HandshakeState` ed esegue `ReadMessage`. Se il tag AEAD fallisce (es. spazzatura iniettata da un relay), Bob scarta il messaggio; la sua effimera $e_B$ e lo stato di retry restano intonsi. Esegue il commit a `Split()` solo se il tag verifica.
3. **Resilienza alla Perdita di `msg 2` (Cache e Retransmit)**:
   - Alice memorizza in cache $\{ e_B, \text{msg2\_bytes}, \text{timestamp\_ultimo\_invio} \}$.
   - Se Alice (in `IN_SESSION`) riceve un `msg 1` valido con la **stessa chiave $e_B$**, re-invia il `msg 2` in cache (rate-limit: max 1 reinvio ogni 1.5s).
   - Se riceve un `msg 1` con $e_B$ differente, lo ignora (stanza monouso).
4. **Anti-Deduplicazione Relay nelle Ripubblicazioni di Bob**:
   - Ogni tentativo di retry di Bob (ogni 3s con jitter, max 60s) genera un **nuovo evento Nostr** con timestamp `created_at` fresco, nuovo event ID e nuova firma, trasportando gli identici 48 byte di `msg 1`.

### 3.2b Gestione dei Messaggi Post-Handshake su Nostr
I messaggi di trasporto Noise (`c1`/`c2`) utilizzano contatori impliciti e richiedono consegna strettamente ordinata. Su Nostr con relay multipli, gli eventi possono arrivare duplicati, riordinati o persi. Si applicano le seguenti regole rigorose:
1. **Nessun Trickle ICE**: si scambia esattamente **una singola offerta SDP** (contenente tutti i candidati ICE raccolti) e **una singola risposta SDP**.
2. **Numero Minimo di Messaggi e Sequenza**: ogni messaggio applicativo include all'interno del plaintext del messaggio Noise (quindi autenticato e cifrato) un campo sequenza progressivo (`seq`).
3. **Ritrasmissione a Byte Identici**: il mittente ritrasmette gli stessi identici byte cifrati (incapsulati in un nuovo evento Nostr) finché non riceve il messaggio successivo atteso dalla controparte.
4. **Deduplicazione e Buffer di Riordino**: il ricevente scarta silenziosamente i tentativi di decifratura falliti (il contatore Noise **non** avanza), deduplica i messaggi tramite hash del ciphertext e mantiene un buffer temporale breve (10 secondi) per riordinare messaggi arrivati in anticipo.
5. **Autenticazione SDP**: SDP e fingerprint DTLS vengono accettati ed elaborati solo se giunti all'interno di `c1`/`c2` **dopo** che il gate SAS è stato superato con successo da entrambi.

### 3.3 Mappatura Direzionale Noise e Derivazione SAS
Al termine dell'handshake, `Split()` produce:
* `h`: handshake hash finale a 32 byte (utilizzato **esclusivamente per la SAS**).
* `c1`: CipherState per la direzione **Bob $\to$ Alice** (Initiator $\to$ Responder).
* `c2`: CipherState per la direzione **Alice $\to$ Bob** (Responder $\to$ Initiator).

#### SAS a 66 bit (6 Parole)
Dall'handshake hash $h$, tramite **HKDF-Expand**, si estraggono 9 byte (72 bit, di cui si utilizzano i primi 66 bit):
$$\text{SAS\_Bytes} = \text{HKDF-Expand}(h, \text{"ANONSHARE-v1-SAS-VERIFICATION"}, 9)$$
I 66 bit vengono partizionati in **6 indici da 11 bit** ($6 \times 11 = 66$), ciascuno mappato su una wordlist standard da 2048 parole (BIP-39 italiana), identica su Web e APK:
$$\text{SAS} = w_{i_1} - w_{i_2} - w_{i_3} - w_{i_4} - w_{i_5} - w_{i_6}$$

### 3.4 Gate di Sicurezza SAS Bloccante
Subito dopo l'handshake, **nessun messaggio SDP/ICE, teaser o metadato del batch di file viene scambiato**:
1. L'interfaccia mostra il gate SAS con le 6 parole e l'avviso esplicito:
   > *"Verifica di sicurezza: confronta queste 6 parole con il tuo interlocutore su un canale diverso da quello in cui hai condiviso il link (a voce o in chiamata)."*
2. **Timeout esteso a 5 minuti**: durante questa schermata l'applicazione gestisce l'eventuale passaggio in background dello smartphone (`visibilitychange`) e riconnessioni WebSocket con resubscribe senza provocare la chiusura prematura della stanza.
3. Solo se entrambi gli utenti confermano la corrispondenza, si sblocca lo scambio SDP/ICE. In caso di annullamento o timeout, la sessione abortisce.

### 3.5 Negoziazione WebRTC P2P e Chiusura Canale Nostr
1. Alice e Bob negoziano SDP e candidati ICE all'interno di `c1`/`c2` su Nostr.
2. Apertura del DataChannel WebRTC configurato con `ordered: true` e `reliable`.
3. **Disconnessione da Nostr**: il canale Nostr viene chiuso e disconnesso **solo dopo aver scambiato con successo un primo messaggio Noise sul DataChannel**, scongiurando qualsiasi desincronizzazione dei contatori crittografici.
4. **Assenza di TURN (Limite Dichiarato)**: in caso di blocco NAT, il client intercetta il timeout ICE e notifica all'utente l'impossibilità di stabilire la connessione diretta.

---

## 4. Modalità Tor (Solo APK con `arti`, tra due APK)

1. **Hosting Onion Service Effimero con Restricted Discovery (Client Authorization v3)**:
   - Alice (Creatore / Responder) avvia un Onion Service v3 effimero tramite `arti` (feature `restricted-discovery` e `vanguards`).
   - Da $S_{\text{room}}$ si deriva la coppia di chiavi client authorization x25519:
     $$\text{AuthKey} = \text{HKDF-Expand}(S_{\text{room}}, \text{"ANONSHARE-v1-HS-CLIENT-AUTH"}, 32)$$
   - Alice configura l'Onion Service per consentire l'accesso **esclusivamente alla chiave pubblica associata**. Nessun nodo Tor o scanner di rete può aprire connessioni verso l'onion service senza possedere $S_{\text{room}}$.
2. **Formato del Link (Onion nel Fragment)**:
   - L'indirizzo onion viene collocato esclusivamente nel frammento URL per non raggiungere server web né anteprime chat:
     `https://<user>.github.io/t/#onion=<random-hash-v3>.onion&secret=<S_room>`
   - Gestito tramite Android App Links verificati gratuiti (`.well-known/assetlinks.json` con `.nojekyll` su GitHub Pages).
3. **Hardening Socket Onion lato Alice**:
   - Verifica AEAD del `msg 1` prima di qualunque altra operazione.
   - Massimo 3 connessioni contemporanee non autenticate.
   - Timeout di handshake: 10 secondi.
   - Frame Noise incapsulati con prefisso di lunghezza a 2 byte (massimo 65535 byte per frame).
   - Chiusura definitiva dell'Onion Service dopo la prima sessione autenticata o a scadenza del TTL (15 minuti).
4. **Flusso Completo Post-Connessione su Tor**:
   - Bob apre il link nell'APK AnonShare e si connette all'onion address di Alice tramite l'istanza `arti` locale (fornendo la chiave di client authorization derivata da $S_{\text{room}}$). Zero Nostr, zero STUN, zero WebRTC.
   - Sullo stream TCP onion, Bob (Initiator) invia `msg 1` e Alice (Responder) risponde con `msg 2`, utilizzando `Noise_NNpsk0_25519_ChaChaPoly_SHA256` con `prologue = "ANONSHARE-v1-TOR"` e framing a prefisso di lunghezza a 2 byte.
   - Segue il medesimo gate SAS bloccante della Sez. 3.4 (6 parole, 66 bit, timeout 5 minuti, confronto vocale su un canale diverso).
   - Dopo il superamento della SAS, tutto il traffico (messaggi di controllo e chunk `DATA`) viaggia sullo stesso socket TCP onion cifrato con `c1`/`c2`, eseguendo le medesime Fasi 1-4 descritte nella Sez. 5.
5. **Isolamento di Rete Rigido nell'APK**:
   - Zero traffico fuori da Tor (WebView inclusa), nessun fallback silenzioso a Modalità Diretta. UI con badge `[🧅 Modalità Tor Attiva]`.

---

## 5. Il Flusso di Scambio: Doppio Consenso Batch e Cancello di Sblocco Reciproco

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Alice (Creatore / Responder)
    actor Bob as Bob (Partecipante / Initiator)

    Note over Alice,Bob: Handshake Noise NNpsk0 su Nostr (o Onion) -> Genera h, c1 (Bob->Alice), c2 (Alice->Bob)
    Note over Alice,Bob: Gate SAS Bloccante a 6 Parole da h (Entrambi confermano prima di procedere)
    Note over Alice,Bob: [ In Mod. Diretta: Scambio SDP/ICE via c1/c2 -> DataChannel WebRTC Aperto ]

    rect rgb(240, 245, 255)
    Note over Alice,Bob: FASE 1: Selezione Batch (max 50 file, <= 100 MB), Bonifica e Offerta Multi-Messaggio
    Alice->>Alice: 1. Bonifica N file (N <= 50, somma declaredMax <= 100 MB)
    Alice->>Alice: 2. Genera salt_Ai (32B), calcola H_Ai = SHA256(salt_Ai || File_Ai)
    Alice->>Alice: 3. Genera Teaser per file (BlurHash default, opzionale Miniatura Chiara <= 8 KB)
    loop Per ogni file i da 0 a N-1
        Alice->>Bob: Invia via c2 (CONTROL): OFFER_ITEM { index: i, commitment: H_Ai, previewMode, blurhash?, thumbnailDataUrl?, declaredMax, mime }
    end
    Alice->>Bob: Invia via c2 (CONTROL): OFFER_END { count: N, totalDeclaredMax }

    Bob->>Bob: Validazione offerta Alice: count == N <= 50, sum(declaredMax) == totalDeclaredMax <= 100 MB, mime in allowlist, thumb <= 8 KB con prefisso "data:image/jpeg;base64," (altrimenti abort)

    Bob->>Bob: 1. Bonifica M file (M <= 50, somma declaredMax <= 100 MB)
    Bob->>Bob: 2. Genera salt_Bj (32B), calcola H_Bj = SHA256(salt_Bj || File_Bj)
    Bob->>Bob: 3. Genera Teaser per file (BlurHash default, opzionale Miniatura Chiara <= 8 KB)
    loop Per ogni file j da 0 a M-1
        Bob->>Alice: Invia via c1 (CONTROL): OFFER_ITEM { index: j, commitment: H_Bj, previewMode, blurhash?, thumbnailDataUrl?, declaredMax, mime }
    end
    Bob->>Alice: Invia via c1 (CONTROL): OFFER_END { count: M, totalDeclaredMax }

    Alice->>Alice: Validazione offerta Bob (stessi controlli stringenti, altrimenti abort)
    end

    Note over Alice,Bob: Entrambi visualizzano la galleria remota (miniature assegnate SOLO a img.src, mai innerHTML)

    rect rgb(255, 250, 240)
    Note over Alice,Bob: FASE 2: Doppio Consenso sul Batch (Noise c1/c2, < 60 KB per messaggio)
    Alice->>Alice: Clicca "Accetta Scambio (M file)"
    Alice->>Bob: Invia via c2 (CONTROL): BATCH_ACCEPT { myCommitments: [H_A0..H_A(N-1)], peerCommitments: [H_B0..H_B(M-1)] }
    Bob->>Bob: Clicca "Accetta Scambio (N file)"
    Bob->>Alice: Invia via c1 (CONTROL): BATCH_ACCEPT { myCommitments: [H_B0..H_B(M-1)], peerCommitments: [H_A0..H_A(N-1)] }
    end

    rect rgb(240, 255, 240)
    Note over Alice,Bob: FASE 3: Rivelazione Salt (Array Posizionale) e Streaming con Tetto Byte Rigido
    Alice->>Bob: Invia via c2 (CONTROL): BATCH_SALTS { salts: [salt_A0, salt_A1, ..., salt_A(N-1)] }
    Bob->>Alice: Invia via c1 (CONTROL): BATCH_SALTS { salts: [salt_B0, salt_B1, ..., salt_B(M-1)] }

    par Streaming Alice -> Bob
        loop Per fileIndex da 0 a N-1
            Alice->>Bob: FILE_START { fileIndex, totalBytes }
            Note over Bob: Controllo Bob: totalBytes <= declaredMax[fileIndex]. Se maggiore -> Abort & Wipe!
            Alice->>Bob: Stream DATA [0x02, uint16 fileIndex, chunk_bytes...] (16 KiB ciascuno)
            Note over Bob: Bob accumula byte: se ricevuti > declaredMax[fileIndex] -> Abort & Wipe!
            Alice->>Bob: FILE_END { fileIndex, totalBytes }
            Note over Bob: Bob controlla: totalBytes == byte_ricevuti == fileStart.totalBytes.<br/>Verifica magic bytes con MIME dichiarato.<br/>Verifica SHA256(salts[fileIndex] || File) == H_Ai.<br/>Se fallisce -> Abort & Wipe!
        end
        Note over Bob: Bob ha tutti i file di Alice -> I file restano BLOCCATI in RAM (nessun URL Blob)
    and Streaming Bob -> Alice
        loop Per fileIndex da 0 a M-1
            Bob->>Alice: FILE_START { fileIndex, totalBytes }
            Note over Alice: Controllo Alice: totalBytes <= declaredMax[fileIndex]. Se maggiore -> Abort & Wipe!
            Bob->>Alice: Stream DATA [0x02, uint16 fileIndex, chunk_bytes...] (16 KiB ciascuno)
            Note over Alice: Alice accumula byte: se ricevuti > declaredMax[fileIndex] -> Abort & Wipe!
            Bob->>Alice: FILE_END { fileIndex, totalBytes }
            Note over Alice: Alice controlla: totalBytes == byte_ricevuti == fileStart.totalBytes.<br/>Verifica magic bytes con MIME dichiarato.<br/>Verifica SHA256(salts[fileIndex] || File) == H_Bj.<br/>Se fallisce -> Abort & Wipe!
        end
        Note over Alice: Alice ha tutti i file di Bob -> I file restano BLOCCATI in RAM (nessun URL Blob)
    end
    end

    rect rgb(255, 240, 245)
    Note over Alice,Bob: FASE 4: Cancello di Sblocco Reciproco (Reciprocal Completion Gate)
    Alice->>Bob: Invia via c2 (CONTROL): BATCH_RECEIVE_COMPLETE { confirmedItemCount: M }
    Note over Alice: Alice in attesa: "Ricezione completata. In attesa del completamento del peer..."<br/>"Se la connessione cade adesso, nessuno dei due terrà i file"
    Bob->>Alice: Invia via c1 (CONTROL): BATCH_RECEIVE_COMPLETE { confirmedItemCount: N }
    Note over Bob: Bob in attesa: "Ricezione completata. In attesa del completamento del peer..."<br/>"Se la connessione cade adesso, nessuno dei due terrà i file"
    Note over Alice,Bob: Ricezione bilaterale di BATCH_RECEIVE_COMPLETE verificata -> SBLOCCO SIMULTANEO DEI FILE IN GALLERIA
    end

    Note over Alice,Bob: File sbloccati nella galleria finale: estensione sicura da allowlist MIME, download individuale o "Scarica Tutti"
```

### Dettaglio Fasi del Protocollo di Scambio:

#### Fase 1: Offerta Multi-Messaggio Compliant con i Frame Noise
Il limite massimo per frame di trasporto Noise NNpsk0 è **65535 byte**. L'offerta viene inviata come sequenza di messaggi:
- **`OFFER_ITEM`** (uno per ciascun file $i = 0 \dots N-1$): payload `{ index: i, commitment: H_i, previewMode, blurhash?, thumbnailDataUrl?, declaredMax, mime }`.
- **`OFFER_END`**: payload `{ count: N, totalDeclaredMax }`.
- **Teaser per File**:
  - *Standard (BlurHash)*: stringa alfanumerica di 25-30 caratteri (default).
  - *Permissivo (Miniatura Chiara)*: micro-thumbnail JPEG ($120 \times 90$, $\le 8\text{ KB}$, prefisso `data:image/jpeg;base64,`) generata esclusivamente dal canvas post-bonifica.
  - *Fallback Automatico*: Se dopo il secondo passaggio di compressione (qualità 0.45) la data URL supera ancora 8 KB, il client ripiega su `previewMode = 'blurhash'` per quel file e notifica la UI con avviso discreto.

#### Fase 2: Doppio Consenso sul Batch
Entrambe le parti scambiano:
$$\text{BATCH\_ACCEPT} = \{ \text{myCommitments: } [H_0 \dots H_{N-1}], \text{peerCommitments: } [H_{\text{peer},0} \dots H_{\text{peer},M-1}] \}$$
Con 50 file per lato, il payload JSON misura $\sim 7.5\text{ KB} \ll 60\text{ KB}$.

#### Fase 3: Rivelazione Salt (Array Posizionale) e Streaming Ordinato
- **`BATCH_SALTS`**: array indicizzato per posizione `{ salts: [salt_0, salt_1, ..., salt_N-1] }` dove `salts[i]` è il salt a 32 byte (in hex) del file $i$. Nessun uso di ID o estensioni arbitrarie ricevute dal peer.
- **Streaming Ordinato e Chiusura per File**: ciascun file viene preceduto da `FILE_START { fileIndex, totalBytes }`, seguito dai chunk `DATA` e terminato da `FILE_END { fileIndex, totalBytes }`.
- I file ricevuti e validati con $H_i = \text{SHA256}(\text{salts}[i] \mathbin{\Vert} \text{File})$ vengono custoditi **bloccati in RAM** (`lockedReceivedFiles`) senza esporre Blob URL.

#### Fase 4: Cancello di Sblocco Reciproco (Reciprocal Completion Gate)
- Quando un client ha ricevuto e verificato tutti i file attesi, invia `BATCH_RECEIVE_COMPLETE { confirmedItemCount }`.
- **Garanzia di Non-Asimmetria**: questo meccanismo *riduce l'asimmetria tra i due utenti nel caso di client non manomessi; non è un meccanismo atomico*. Impedisce che la parte che termina per prima possa visualizzare o salvare i file prima che anche la controparte abbia completato.
- In UI compare lo stato di attesa con avviso esplicito:
  > *"Ricezione completata. In attesa del completamento del peer..."*
  > <br/>
  > **"Se la connessione cade adesso, nessuno dei due terrà i file"**
- Se la connessione cade o un peer invia dati errati prima del consenso bilaterale, la sessione abortisce e la memoria RAM viene istantaneamente azzerata (*wipe*).
- Solo alla conferma bilaterale i file vengono sbloccati nella galleria finale.

---

## 6. Cifratura dei Chunk con Noise Transport

Tutti i blocchi dei file del batch vengono trasferiti direttamente come messaggi di trasporto Noise:
* **Formato del Plaintext `DATA`**:
  - Byte 0: `0x02` (indicatore di tipo `DATA`).
  - Byte 1..2: Big-endian `uint16` `fileIndex` indicante a quale file del batch appartiene il blocco ($0 \dots N-1$).
  - Byte 3..N: blocco di dati binari grezzi (dimensione standard: **16 KiB = 16384 byte** per blocco).
* **Cifratura**:
  - I blocchi da Bob ad Alice sono cifrati con `c1.EncryptWithAd(ad="", plaintext)`.
  - I blocchi da Alice a Bob sono cifrati con `c2.EncryptWithAd(ad="", plaintext)`.
* **Protezioni Fornite Nativamente da Noise**:
  - Nonce incrementale a 64 bit gestito internamente dal CipherState di Noise (nessuna possibilità di riutilizzo).
  - Autenticazione crittografica ChaCha20-Poly1305 (tag da 16 byte) su ciascun blocco.
  - Re-ordering e troncamento impediti dalla combinazione del contatore Noise, del prefisso `fileIndex`, dei messaggi `FILE_START`/`FILE_END` e del commitment finale $H_i$.
* **Obiettivo Prestazionale**: trasferimento di un batch da **100 MB in pochi secondi su un dispositivo medio**, verificato strumentalmente in fase di benchmark.

---

## 7. Bonifica dei Metadati e Gestione Formati

### Immagini (JPEG, PNG, WebP)
* **Canvas Re-Encoding**:
  - Decodifica locale e ridisegno su elemento `<canvas>` offscreen.
  - Rigenerazione di un nuovo blob (JPEG 95% o WebP).
  - Eliminazione totale a monte di EXIF, IPTC, XMP, coordinate GPS, modello fotocamera e commenti.
  - $H_i$, BlurHash e miniatura vengono calcolati esclusivamente sulla copia ripulita dal canvas.

### Formato HEIC / HEIF
* Riconoscimento magic bytes `ftypheic` / `ftypmif1`.
* Conversione client-side via WebAssembly (`heic2any`) se supportata, altrimenti blocco immediato con messaggio chiaro: *"Formato HEIC non supportato: convertilo prima in JPEG o PNG."*

### Audio e Video (MP3, FLAC, MP4, WebM) — Sanificazione Best Effort
* **Audio (MP3 / FLAC)**: Parser di container standard per rimuovere tag ID3v1/ID3v2 e commenti Vorbis.
* **Video (MP4)**:
  - Ispezione del container `moov`:
    - Espunzione selettiva dei box utente `udta` (tag `©xyz`, `loci`) e dei box metadata `meta` (item `com.apple.quicktime.location.ISO6709`, camera tags).
    - **Azzeramento Timestamp**: impostazione a zero (epoch standard) dei campi `creation_time` e `modification_time` presenti negli atom header `mvhd` (Movie Header), `tkhd` (Track Header) e `mdhd` (Media Header).
  - *Dichiarazione Best Effort*: Metadati di telemetria continui o tracce GPS temporizzate frame-by-frame non sono garantite come rimosse senza ricodifica video totale.
* **Video (WebM)**: Rimozione degli elementi `Tag` e `SimpleTag` del contenitore EBML.

### Formati Esclusi (Fuori dalla v1)
* **Documenti PDF**: Esclusi dalla v1 (richiedono parser dedicato per stream interni e revisioni).

### Anteprime Selettive: Teaser BlurHash e Miniatura Chiara Permissiva
* **BlurHash Standard**:
  - Generazione locale su canvas a bassa risoluzione ($4 \times 3$ componenti).
  - Stringa alfanumerica di 25-30 caratteri inviata solo nel canale cifrato Noise (`c1`/`c2`).
* **Miniatura Chiara Permissiva**:
  - Scelta facoltativa per singolo file operata dal mittente.
  - Generata **esclusivamente dal canvas post-bonifica** (zero EXIF/GPS residui).
  - Vincolo rigido: max $120 \times 90$ pixel, dimensione massima **8 KB** (8192 byte), codifica JPEG con prefisso tassativo `data:image/jpeg;base64,`.
  - Compressione progressiva in due passaggi (qualità 0.60 e 0.45): se supera ancora 8 KB, **fallback automatico a BlurHash** con avviso discreto in UI.
  - Video: estrazione fotogramma al secondo 0.5 su canvas bonificato, con fallback se codec non decodificabile.
  - Avvertenza esplicita in interfaccia sul selettore permissivo:
    > *"L'altra persona vedrà questa immagine prima di accettare lo scambio"*

---

## 8. Hardening del Client e Protezione File Ricevuti

### Allowlist Magic Bytes Rigida (Solo Media v1)
* **JPEG**: `FF D8 FF`
* **PNG**: `89 50 4E 47 0D 0A 1A 0A`
* **WebP**: `52 49 46 46 ... 57 45 42 50`
* **MP4**: `00 00 00 ... 66 74 79 70` (`ftyp`)
* **WebM**: `1A 45 DF A3` (EBML Header)
* **MP3**: `49 44 33` (`ID3`) oppure sync frame `FF FB` / `FF F3` / `FF F2`
* **FLAC**: `66 4C 61 43` (`fLaC`)

A fine ricezione di ciascun file, i magic bytes vengono verificati rispetto al MIME dichiarato (`verifyMagicBytesForMime`). In caso di incongruenza o formato fuori allowlist, il file viene scartato e la sessione abortita immediatamente.

### Controlli Dimensionali, Validazione Batch e Anti-Bomb
1. **Limiti del Batch**: Massimo **50 file per batch** e limite aggregato complessivo di **100 MB** (`MAX_BATCH_FILES = 50`, `MAX_BATCH_TOTAL_BYTES = 100 * 1024 * 1024`).
2. **Validazione dell'Offerta Lato Ricevente**:
   - `count <= 50` e uguale al numero di `OFFER_ITEM` ricevuti.
   - Somma dei `declaredMax` per ciascun file $\le 100\text{ MB}$ e strettamente identica a `totalDeclaredMax` dichiarato in `OFFER_END`.
   - Ciascun MIME deve appartenere alla allowlist fissa.
   - Se `previewMode === 'thumbnail'`: miniatura $\le 8\text{ KB}$ e prefisso obbligatorio `data:image/jpeg;base64,`.
   - Se una qualunque verifica fallisce $\to$ **abort immediato con errore esplicito**.
3. **Assegnazione Sicura nel DOM**:
   - Le miniature ricevute vengono caricate **esclusivamente tramite la proprietà `img.src`** di elementi creati programmaticamente (`document.createElement('img')`), **mai tramite `innerHTML`** né interpolazione HTML, prevenendo ogni rischio XSS.
4. **Validazione dello Streaming e Tetto Byte**:
   - **`FILE_START`**: abort e wipe RAM se `totalBytes > declaredMax` dell'item corrispondente.
   - **Chunk `DATA`**: accettati solo tra `FILE_START` e `FILE_END` del file attivo. Il prefisso `fileIndex` deve corrispondere all'indice atteso (strettamente crescente da $0$ a $\text{count}-1$). Se arriva un chunk fuori ordine, fuori range o fuori dalla finestra attiva $\to$ abort immediato e **azzeramento dei buffer in RAM**.
   - **Accumulo Byte**: se i byte cumulativi del file attivo superano `declaredMax` $\to$ abort immediato e wipe RAM.
   - **`FILE_END`**: abort e wipe RAM se `totalBytes` non coincide coi byte ricevuti o con quello di `FILE_START`.
5. **Controllo Risoluzione Immagini Pre-Decode**: Prima di istanziare un'immagine in memoria per il rendering, il client ispeziona l'header del file per estrarre larghezza e altezza in pixel. Limite massimo consentito: **$8192 \times 8192$ pixel** (massimo ~40 megapixel complessivi), prevenendo memory exhaustion / decompression bomb sul motore grafico.
6. **Derivazione Rigorosa di Estensione e Nome File**:
   - Il campo `extension` inviato dal peer viene completamente **ignorato**.
   - L'estensione del file salvato è determinata unicamente dalla tabella interna MIME $\to$ estensione (`image/jpeg` $\to$ `.jpg`, `image/png` $\to$ `.png`, `image/webp` $\to$ `.webp`, `video/mp4` $\to$ `.mp4`, `video/webm` $\to$ `.webm`, `audio/mpeg` $\to$ `.mp3`, `audio/flac` $\to$ `.flac`).
   - Il nome del file salvato è generato localmente con numerazione progressiva: `anon_YYYYMMDD_xxxx_01.ext`.
7. **Isolamento Sandboxed**: Eventuali anteprime post-scambio avvengono in `<iframe sandbox="" srcdoc="..."></iframe>` passivo (zero privilegi di script) o tag media sandboxed.

---

## 9. Uso Responsabile dei Relay Nostr Pubblici

1. **Esclusivamente Eventi Effimeri (kind 20000–29999)**: I messaggi transitano solo nella RAM dei relay verso i client attivi e non vengono salvati su disco/database.
2. **Consumo di Banda Minimo**:
   - `msg 1` Noise (Initiator): 48 byte di payload Noise (~150 byte per l'evento Nostr complessivo).
   - `msg 2` Noise (Responder): 48 byte di payload Noise (~150 byte per l'evento Nostr complessivo).
   - Negoziazione SDP/ICE: ~1-2 KB.
   - Totale sessione: **meno di 10 eventi complessivi, volume inferiore a 10 KB**.
3. **Nessun Dato Multimediale**: I file del batch e i relativi chunk **non toccano mai la rete Nostr**, transitando unicamente sul DataChannel WebRTC diretto.

---

## 10. Modello di Fiducia del Codice: Web vs APK

* **Versione Web (PWA)**:
  - *Modello di Fiducia*: L'utente deve fidarsi del server di hosting (es. GitHub Pages) al primo caricamento della pagina HTML. Subresource Integrity (SRI) protegge i soli asset JavaScript e CSS referenziati, non il file `index.html` principale.
  - *Hosting*: GitHub Pages non è immutabile (può essere aggiornato con nuovi commit).
  - *Dipendenze in Bundle Locale*: Librerie di terze parti (`heic2any`, `blurhash`, implementazione Noise in TS) impacchettate localmente nel repository con lockfile deterministico, senza dipendenza da CDN esterne a runtime.
  - *Content Security Policy*: Dichiarata all'interno del tag `<meta http-equiv="Content-Security-Policy" content="...">` dell'HTML, bloccando connessioni esterne non autorizzate.
* **Versione APK (Android)**:
  - Codice compilato, impacchettato e firmato digitalmente con Android Keystore. Immutabile a runtime, privo di dipendenza dall'hosting web per il codice dell'app.
  - Gestione Android App Links tramite hosting gratuito su `<user>.github.io/.well-known/assetlinks.json` con file `.nojekyll`.

---

## 11. Piano di Test e Verifica Esaustivo

### Test Unitari e di Protocollo Crittografico
1. **Test Handshake Noise NNpsk0 su Nostr (Sincronizzazione Asimmetrica)**:
   - *Caso A (Sottoscrizione Completa)*: Alice crea la stanza ed è in ascolto; Bob si collega e pubblica `msg 1` -> handshake completato al primo tentativo.
   - *Caso B (Ripubblicazione e Anti-Deduplicazione)*: Bob pubblica `msg 1` prima che Alice sia sottoscritta -> Bob ripubblica periodicamente `msg 1` con timestamp `created_at` fresco; Alice riceve il messaggio e conclude l'handshake.
2. **Test Anti-DoS e Simmetria (Spazzatura ed Eco)**:
   - *Test Spazzatura su Alice*: invio di `msg 1` non autenticato -> scartato su stato candidato effimero; Alice non commuta in `IN_SESSION`.
   - *Test Spazzatura o Eco su Bob*: Bob riceve un evento spazzatura come `msg 2` o riceve l'eco del proprio `msg 1` -> scartato su stato candidato effimero; Bob continua il retry e completa l'handshake all'arrivo del vero `msg 2`.
3. **Test Cache e Reinoltro di `msg 2` su `msg 1` Duplicato**:
   - Bob subisce packet drop su `msg 2` e invia un secondo `msg 1` con la stessa effimera $e_B$.
   - *Verifica*: Alice rileva la corrispondenza con la sessione in cache e ritrasmette `msg 2` senza bloccare la stanza.
4. **Test Gate SAS Bloccante (6 Parole / 66 bit)**:
   - Simulazione di mancata corrispondenza del SAS o pressione del pulsante "Annulla" da parte di uno dei client.
   - *Verifica*: Abort immediato della sessione; nessun messaggio SDP o ICE viene scambiato; nessun teaser viene mostrato.
5. **Test Cifratura Dati Noise Transport (`c1`/`c2`)**:
   - *(a) Test Troncamento File*: chiusura connessione prima di `FILE_END` o pacchetto omesso -> file parziale scartato immediatamente.
   - *(b) Test Riordino o Manomissione Chunk*: alterazione o inversione di due blocchi `DATA` -> fallimento Poly1305 di Noise e scarto del file.
   - *(c) Test Discrepanza Byte*: `totalBytes` dichiarato in `FILE_END` diverso dai byte fisici effettivamente ricevuti, oppure byte ricevuti superiori a `declaredMax` -> abort e wipe RAM.
   - *(d) Benchmark*: misurazione dei tempi di cifratura e decifratura di 100 MB nel browser e su Android (target: pochi secondi).
6. **Test Vector Noise e Interoperabilità JS $\leftrightarrow$ Rust**:
   - Esecuzione dei test vector ufficiali del Noise Protocol Framework per `Noise_NNpsk0_25519_ChaChaPoly_SHA256`.
   - Test di interoperabilità tra l'implementazione TypeScript (Web) e `snow` (Rust/APK).
7. **Test Post-Handshake su Nostr (Perdita, Duplicazione, Riordino)**:
   - Simulazione con 4 relay Nostr con iniezione di drop pacchetti, duplicati e riordino dei messaggi di negoziazione SDP -> la sessione gestisce il buffer temporale e conclude con successo la connessione.
8. **Test Apertura Link Tor su Versione Web**:
   - Apertura di un URL `/t/#onion=...&secret=...` nel browser web:
     - *(a)* compare unicamente il messaggio statico informativo;
     - *(b)* ispezione del log di rete: **zero** chiamate WebSocket (Nostr), **zero** RTCPeerConnection e **zero** richieste STUN;
     - *(c)* il frammento URL viene rimosso istantaneamente con `history.replaceState`.

### Test del Protocollo Batch Multi-Media e Sicurezza dei File
9. **Test Invio e Ricezione Offerta Multi-Messaggio a 50 File**:
   - Generazione di un batch di 50 elementi con miniature conformi ($\le 8\text{ KB}$).
   - Invio sequenziale di 50 messaggi `OFFER_ITEM` seguiti da `OFFER_END`.
   - Verifica che il peer non sblocchi l'accettazione prima dell'arrivo di `OFFER_END` e che il conteggio corrisponda esattamente a 50.
10. **Test Rifiuto e Abort Offerta non Conforme**:
    - Batch con somma `declaredMax` $> 100\text{ MB} \to$ abort immediato con eccezione esplicita.
    - Batch con `count` $> 50 \to$ abort immediato.
    - Miniatura priva del prefisso `data:image/jpeg;base64,` o superiore a $8\text{ KB} \to$ abort immediato.
11. **Test Tetto Byte durante lo Streaming**:
    - Ricezione di `FILE_START` con `totalBytes > declaredMax` dell'item $\to$ abort immediato.
    - Streaming di chunk `DATA` cumulativi che superano `declaredMax` del file $\to$ abort immediato e azzeramento (*wipe*) di tutti i buffer in RAM.
    - Ricezione di `FILE_END` con `totalBytes` non coincidente con i byte ricevuti o con `FILE_START` $\to$ abort e wipe RAM.
12. **Test Validazione `fileIndex` e Streaming Fuori Sequenza**:
    - Chunk `DATA` con `fileIndex` fuori sequenza rispetto all'ordine $0 \dots N-1$, oppure ricevuto prima di `FILE_START` $\to$ abort immediato e svuotamento completo della memoria RAM.
13. **Test MIME Allowlist e Verifica Magic Bytes**:
    - Offerta con MIME type non supportato o non in allowlist (es. `application/pdf`) $\to$ abort immediato.
    - File ricevuto con magic bytes incoerenti rispetto al MIME dichiarato (es. byte ASCII camuffati da `image/jpeg`) $\to$ abort immediato, scarto del file e wipe RAM.
    - Verifica che l'estensione del file salvato derivi unicamente dall'allowlist MIME interna, ignorando il campo dichiarato dal peer.
14. **Test Cancello di Sblocco Reciproco e Asimmetria**:
    - Alice trasmette 3 file, Bob ne trasmette 1 pesante.
    - Alice termina per prima la ricezione: verifica transizione a `waiting_peer_completion` senza alcun rilascio di URL Blob o file.
    - Bob termina e invia `BATCH_RECEIVE_COMPLETE`: sblocco simultaneo e bilaterale della galleria nello stato `completed`.
    - Disconnessione anticipata durante l'attesa reciproca: verifica che i buffer vengano azzerati e che nessun file rimanga accessibile.
15. **Test Fallback Miniatura Automatica**:
    - Simulazione di miniatura che eccede 8 KB anche a qualità 0.45 $\to$ fallback automatico trasparente su `previewMode = 'blurhash'` senza sollevare errori bloccanti.

### Test di Rete e Resilienza Senza Server
16. **Test Accettazione Kind Effimeri sul Pool Nostr**:
    - Script automatizzato per verificare che tutti i relay configurati nel pool (`damus.io`, `nos.lol`, `primal.net`) accettino e inoltrino eventi kind 20000+ senza richiedere autenticazione NIP-42 o pagamenti.
17. **Test Resilienza Relay Nostr (Failover su Pool Ridondante)**:
    - Simulazione di 2 relay Nostr offline nel pool di 4 relay configurati -> handshake stabilito attraverso i relay rimanenti.
18. **Test Fallimento NAT Traversal (Assenza TURN)**:
    - Simulazione di due client posti dietro NAT simmetrici restrittivi -> intercettazione del timeout ICE e notifica all'utente entro 15 secondi, senza stallo.

### Test di Hardening, Bonifica Metadati e Magic Bytes (Audit con `exiftool`)
19. **Test Limiti Dimensionali (Byte e Pixel)**:
    - *Test Byte*: Invio di un file che supera i byte dichiarati o i 100 MB -> abort immediato del trasferimento.
    - *Test Pixel*: Invio di un'immagine con risoluzione header di $10000 \times 10000$ pixel -> rifiuto prima del rendering su canvas.
20. **Test Re-Encoding Immagini e Gestione HEIC**:
    - Esecuzione `exiftool` su JPEG/PNG post-canvas: zero tag EXIF/GPS/IPTC residui.
    - Test gestione file `.heic`: conversione o blocco con avviso chiaro.
21. **Test Bonifica Audio e Video (`exiftool`)**:
    - **MP3**: Rimozione tag ID3 con `exiftool`.
    - **FLAC**: Rimozione commenti Vorbis con `exiftool`.
    - **MP4 (Video Smartphone con GPS)**: Test con video girato da smartphone contenente GPS in `udta`/`meta` e timestamp in `mvhd`/`tkhd`/`mdhd`. Esecuzione `exiftool`: assenza totale di coordinate GPS (`GPSCoordinates`, `QuickTime:Location`, `©xyz`) e timestamp di creazione/modifica azzerati.
    - **WebM**: Rimozione tag EBML con `exiftool`.
22. **Test Isolamento Iframe**:
    - Verifica che l'iframe adotti `sandbox=""` privo di privilegi di esecuzione.

---

## 12. Limiti Noti Dichiarati (Cosa l'app NON può fare)
1. **Nessun Anonimato IP nella Modalità Diretta (Web / APK)**: In Modalità Diretta, WebRTC richiede la connessione P2P tra gli endpoint. I due utenti vedono reciprocamente i propri indirizzi IP; i relay Nostr e i server STUN vedono gli IP di connessione.
2. **Connessione Non Garantita al 100% (Assenza di Server TURN)**: Per rispettare il vincolo a costo zero e zero server gestiti, non viene fornito alcun server TURN. Reti con NAT simmetrici restrittivi non potranno stabilire il collegamento P2P.
3. **Dipendenza dalla Disponibilità dei Relay Nostr Pubblici**: La Modalità Diretta richiede che almeno uno dei relay Nostr pubblici aperti sia raggiungibile e operativo.
4. **Il Teaser BlurHash Non Protegge da Dizionari di Immagini Note**: Se la controparte possiede già l'immagine specifica scambiata, il confronto visuale o percettivo del BlurHash con dimensione e MIME può confermarne l'identità prima dell'accettazione. La protezione con salted hash $H_i$ protegge il payload binario, non l'anteprima visiva.
5. **Anteprima Chiara Permissiva**: L'attivazione dell'anteprima chiara trasmette una miniatura riconoscibile all'altra persona prima che quest'ultima abbia accettato lo scambio; l'utente deve essere consapevole di questa scelta (segnalata esplicitamente in UI).
6. **Sanificazione Video Best Effort**: La rimozione dei metadati nei video MP4/WebM è limitata ai box container standard (`udta`, `meta`, timestamp `mvhd`/`tkhd`/`mdhd`); tracce di geolocalizzazione continue o telemetrie interne ai frame non sono garantite come rimosse.
7. **Fiducia nell'Host per la Versione Web**: Al primo caricamento, l'utente della versione Web si fida dell'host per l'integrità di `index.html`.
8. **Scambio Non Atomico (Cancello Reciproco)**: Il cancello di sblocco reciproco post-trasferimento (`BATCH_RECEIVE_COMPLETE`) **riduce l'asimmetria tra i due utenti nel caso di client non manomessi; non è un meccanismo atomico**. Se la parte A esegue un client malevolo decompilato che memorizza i chunk raw man mano che arrivano, la parte A può conservare i file di B anche disconnettendosi prima di completare l'invio. Senza un garante fidato (TTP), la protezione da asimmetria opera assumendo client conformi.
9. **Documenti Fuori dalla v1**: I documenti (inclusi PDF) non sono supportati nella v1.

---

## 13. Decisioni e Scelte Architetturali

### Decisioni Chiuse
* **DECISIONE APERTA 4: Chiusa con Adozione di Restricted Discovery (Client Authorization v3)**
  * La documentazione ufficiale di `arti` conferma la stabilità della feature `restricted-discovery` (da Arti 1.7.0) e del supporto `vanguards` (da 1.2.2).
  * La chiave x25519 di client authorization viene derivata direttamente da $S_{\text{room}}$ via HKDF (`"ANONSHARE-v1-HS-CLIENT-AUTH"`): Alice autorizza unicamente tale chiave sull'Onion Service.
  * *Verifiche in fase di implementazione*: fornitura della chiave lato Bob senza persistenza su disco, build Android/Tauri con `onion-service-service`, e PoW lato servizio. Se la restricted discovery dovesse presentare incompatibilità su Android, fallback al controllo di autenticazione AEAD sul socket.

### Scelte Effettuate tra Alternative e Rationale
1. **Cifratura Dati Unica su Noise Transport (Opzione A Aggiornata)**:
   * *Rationale*: In `Noise_NNpsk0`, $h$ è recomputabile da chiunque conosca il link e abbia osservato l'handshake; derivare chiavi da $h$ vanificava la Forward Secrecy per i dati. Utilizzare direttamente i CipherState `c1` e `c2` per inviare i chunk post-consenso garantisce PFS reale su tutto il payload senza librerie crittografiche ridondanti (`libsodium.js` rimossa).
2. **SAS a 66 bit da $h$ (6 parole su wordlist 2048 parole)**:
   * *Rationale*: Fornisce un channel binding matematico e una difesa efficace contro chi intercetta il link prima dell'handshake, con entropia adeguata e usabilità eccellente.
3. **Android App Links Gratuiti su GitHub Pages**:
   * *Rationale*: Elimina i costi di un dominio proprietario (`anonshare.app`) rispettando il vincolo zero-costi e scongiurando il rischio di dirottamento degli schemi URI personalizzati.
4. **Simmetria Anti-DoS su Nostr con Scarto Rigido 48 Byte**:
   * *Rationale*: Sia Alice che Bob sono protetti da tentativi di DoS o saturazione dello stato causati da relay o utenti malevoli.
5. **Offerta Multi-Messaggio (`OFFER_ITEM` + `OFFER_END`) e Framing DATA con `fileIndex`**:
   * *Rationale*: Con un limite massimo per frame Noise fissato a 65535 byte, un'offerta batch contenente fino a 50 file con miniature non può essere stipata in un singolo messaggio di controllo. La sequenza `OFFER_ITEM` seguita da `OFFER_END` e il prefisso a 2 byte `fileIndex` garantiscono totale compatibilità con il framing Noise e isolamento tra file durante lo streaming.
