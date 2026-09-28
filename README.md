# AnonShare

Zero-Server, Zero-Knowledge Peer-to-Peer Encrypted File Exchange.

AnonShare is a client-side web application designed for direct, bilateral file exchanges between two parties without proprietary central servers, user accounts, tracking, or intermediary storage. All data transfers occur directly peer-to-peer using WebRTC DataChannels, protected by authenticated end-to-end encryption via the Noise Protocol Framework.

---

## Architectural Highlights

- **Zero-Server Infrastructure**: No backend servers, databases, or cloud storage. Signaling uses public decentralized Nostr relays, and media files travel directly between client browsers.
- **Noise Protocol Handshake (NNpsk0)**: Authenticated key agreement over ephemeral public relays using Curve25519, ChaCha20-Poly1305, and SHA-256 with a pre-shared key embedded into the one-time room link.
- **WebRTC DataChannel Streaming**: Direct peer-to-peer transfer with binary framing, flow pacing, and zero intermediary retention.
- **Dual Consent & Cryptographic Commitments**: Neither peer can access or decrypt files until both participants have explicitly inspected the offers and confirmed the exchange. File commitments are bound mathematically:
  $$\text{Commitment} = \text{SHA-256}(\text{salt} \parallel \text{file})$$
- **Client-Side Sanitization**: EXIF and metadata stripping for images and media before preview generation or transmission.
- **Privacy-Preserving Previews**: Support for Blurhash representations and compact sanitized thumbnails without revealing raw files prior to reciprocal agreement.
- **Live Offer Negotiation**: Dynamic adjustment of batch files and preview clarity with automatic state synchronization (`OFFER_RESET`) and instant consent revocation upon modification.
- **Strict Content Security Policy (CSP)**: Sandboxed browser environment preventing third-party script injections, unauthorized analytics, or external data exfiltration.

---

## Protocol Overview

```
Alice                                                     Bob
  |                                                        |
  | -------- Nostr Ephemeral Event (Noise Handshake) ----> |
  | <------- Nostr Ephemeral Event (Noise Handshake) ----- |
  |                                                        |
  | <============= WebRTC DataChannel Connected =========> |
  |                                                        |
  | -- OFFER_ITEM(s) + OFFER_END [Commitments + Blurhash]->|
  | <-- OFFER_ITEM(s) + OFFER_END [Commitments + Blurhash]-|
  |                                                        |
  | [Both peers review metadata/previews in browser UI]    |
  |                                                        |
  | -- BATCH_ACCEPT [Dual Consent Confirmation] ---------> |
  | <-- BATCH_ACCEPT [Dual Consent Confirmation] --------- |
  |                                                        |
  | -- BATCH_SALTS + FILE_START + DATA Chunks -----------> |
  | <-- BATCH_SALTS + FILE_START + DATA Chunks ----------- |
  |                                                        |
  | [Commitment Verification & Memory-Safe Download]       |
```

1. **Signaling Phase**: The initiator generates a one-time cryptographic room secret. A short-lived pairing identifier is exchanged via public Nostr relays (`relay.damus.io`, `nos.lol`, etc.) using NIP-01 ephemeral events (kind 20000+).
2. **Noise Key Exchange**: The peers complete an NNpsk0 handshake, producing independent forward-secure cipher states (`c1`, `c2`) for authenticated bidirectional encryption.
3. **P2P Channel Setup**: WebRTC peer connection is negotiated through encrypted Nostr messages. Once the direct DataChannel opens, Nostr transport is immediately closed.
4. **Offer & Verification**: Cryptographic commitments and sanitized Blurhash previews are transmitted. If an offer is updated or toggled, existing consent is revoked.
5. **Dual Consent & Streaming**: When both peers confirm, salts are revealed and files are streamed in 16 KiB encrypted chunks.
6. **Integrity Enforcement**: Each received file is validated against its declared SHA-256 commitment before being assembled into memory for user download.

---

## Getting Started

### Prerequisites

- Node.js (version 20 or later recommended)
- npm (version 10 or later)

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/icaro12123/anon-share.git
cd anon-share
npm install
```

### Development Server

Start the local Vite development server:

```bash
npm run dev
```

The application will be accessible at `http://localhost:5173`.

### Automated Testing

Run the Vitest test suite covering cryptographic primitives, Noise protocol benchmarks, handshake flows, and batch transfer scenarios:

```bash
npm test
```

### Production Build

Compile TypeScript and build the optimized production assets:

```bash
npm run build
```

The compiled files will be output to the `dist/` directory.

To test the production build locally:

```bash
npm run preview
```

---

## Deployment

AnonShare is a completely static, client-side web application. It requires no application server and can be hosted on any static hosting platform supporting HTTPS.

### GitHub Pages

A ready-to-use GitHub Actions workflow is provided in `.github/workflows/deploy.yml`.

1. Go to your repository settings on GitHub.
2. Navigate to **Pages** in the left sidebar.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. The site will automatically build and deploy on every push to the `main` branch.

### Vercel / Cloudflare Pages / Netlify

1. Import the repository into your platform of choice.
2. Build command: `npm run build`
3. Output directory: `dist`
4. Deploy.

*Note: A secure context (HTTPS) is mandatory in production. Modern web browsers strictly disable WebRTC, SubtleCrypto, and Clipboard APIs over unencrypted HTTP.*

---

## Security & Privacy Considerations

- **No Central Custody**: No file data, metadata, IP logs, or session tokens are ever sent to or stored on a central server.
- **RAM-Only Processing**: Received chunks remain in temporary browser memory until verified and downloaded by the user. If an error or commitment mismatch occurs, buffers are wiped immediately.
- **Short-Lived Sessions**: Room identifiers and cryptographic keys are ephemeral and discarded once the browser session terminates.
- **No Third-Party Analytics**: Zero external tracking scripts, telemetry, cookies, or remote fonts.

---

## Acceptable Use Policy & Legal Disclaimer

### 1. Purpose and Permitted Use

AnonShare is developed and provided as an open-source, dual-use technology intended exclusively for lawful, private, and personal peer-to-peer file transfers, privacy research, and secure communications.

### 2. Prohibited Uses

Users agree not to use AnonShare for any unlawful activities. It is strictly prohibited to transmit, distribute, or facilitate the exchange of:

- Child Sexual Abuse Material (CSAM) or any form of child exploitation.
- Malicious software, viruses, ransomware, trojans, or tools designed for unauthorized network intrusion.
- Unlawfully obtained, classified, or stolen materials.
- Content that infringes on third-party intellectual property rights, copyrights, trademarks, or trade secrets without authorization.
- Any content or material that violates applicable local, national, or international laws and regulations.

### 3. User Responsibility & Absence of Intermediary Control

AnonShare operates as an automated, serverless peer-to-peer utility. The developers and contributors:

- Do not operate intermediary servers, proxies, or databases handling user payload data.
- Do not possess cryptographic access, private keys, or technical capabilities to monitor, inspect, filter, moderate, or decrypt user transmissions.
- Do not store, log, or index file contents, user identities, or transfer histories.

Each individual user bears sole and exclusive legal responsibility for the nature, legality, and consequences of any data transmitted or received using this software.

### 4. Disclaimer of Warranty

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS, DEVELOPERS, OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## License

This project is licensed under the [MIT License](LICENSE).
