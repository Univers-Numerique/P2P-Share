/* ═══════════════════════════════════════════════════════════════
   P2P Share — app.js
   WebRTC peer-to-peer file transfer (PeerJS) with Socket.io signaling
   and relay fallback. Files and metadata are end-to-end encrypted
   (AES-256-GCM) with a key that only lives in the invite link's #fragment.
   ═══════════════════════════════════════════════════════════════ */

'use strict';

// ── CONFIG ────────────────────────────────────────────────────────
const CHUNK_SIZE = 64 * 1024;             // plaintext bytes per chunk
const P2P_HIGH_WATER = 1024 * 1024;       // pause sending above this DataChannel buffer
const RELAY_WINDOW = 8;                   // relay chunks in flight before waiting for acks
const TRANSFER_IDLE_MS = 30_000;
const PSEUDO_MAX = 24;
const TAG_LEN = 20;                       // 16 bytes transferId (ascii hex) + 4 bytes chunk index
const IV_LEN = 12;
const ID_RE = /^[0-9a-f]{16}$/;
const SALON_RE = /^[0-9a-f]{8}$/;
const KEY_RE = /^[A-Za-z0-9_-]{22}$/;
const SESSION_KEY = 'p2pshare-session';
const PSEUDO_KEY = 'p2pshare-pseudo';
const PREVIEW_MAX_BYTES = 300 * 1024 * 1024;  // larger remote files must be downloaded before opening
const TEXT_PREVIEW_MAX = 1024 * 1024;

// Previewable formats, keyed by extension. The MIME type always comes from this table,
// never from the sender, so a remote file can't make the browser render it as HTML.
const TEXT_EXTS = 'txt md csv tsv json log xml yml yaml ini conf toml sql js mjs ts jsx tsx css scss html htm py java c h cpp hpp cs go rs php rb sh bat ps1 kt swift';
const PREVIEW_TYPES = {
  image: { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', bmp: 'image/bmp', ico: 'image/x-icon', svg: 'image/svg+xml' },
  video: { mp4: 'video/mp4', m4v: 'video/mp4', webm: 'video/webm', ogv: 'video/ogg', mov: 'video/quicktime' },
  audio: { mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', oga: 'audio/ogg', opus: 'audio/ogg', flac: 'audio/flac', aac: 'audio/aac', m4a: 'audio/mp4' },
  pdf:   { pdf: 'application/pdf' },
  text:  Object.fromEntries(TEXT_EXTS.split(' ').map(ext => [ext, 'text/plain; charset=utf-8']))
};

const PSEUDO_ADJECTIVES = ['Rapide','Véloce','Calme','Sombre','Brillant','Furtif','Noble','Vif','Sage','Fou','Libre','Doux','Fort','Fier','Brave'];
const PSEUDO_ANIMALS    = ['Léopard','Aigle','Renard','Tigre','Hibou','Cobra','Loup','Puma','Lynx','Faucon','Ours','Jaguar','Vautour','Bison','Daim'];
const AVATAR_CLASSES    = ['av-0','av-1','av-2','av-3','av-4'];

// ── STATE ─────────────────────────────────────────────────────────
let socket = null;
let peer = null;
let iceServers = null;
let salonId = null;
let salonKey = null;        // base64url secret, never sent to the server
let cryptoKey = null;       // AES-GCM key derived from salonKey
let authToken = null;       // derived from salonKey, proves knowledge of the key to the server
let myPseudo = '';
let isHost = false;
let myMemberId = null;       // stable identity in the salon, survives reconnections
let sessionToken = null;     // proves that identity to the server when resuming
let zipping = false;

// members: Map<memberId, { pseudo, isHost, peerId, conn, retries, retryTimer }>
const members = new Map();
// myFiles: Map<fileId, { file, name, size, mimeType }>
const myFiles = new Map();
// remoteFiles: Map<fileId, { fileId, name, size, mimeType, senderMemberId, senderPseudo }>
const remoteFiles = new Map();
// downloads: Map<transferId, incoming transfer>
const downloads = new Map();
// uploads: Map<transferId, { fileId, to, via, pseudo, pct, cancelled }>
const uploads = new Map();
// localCopies: Map<fileId, Blob | FileSystemFileHandle> — downloaded remote files that can be reopened
const localCopies = new Map();

// ── UTILS ─────────────────────────────────────────────────────────
function randomPseudo() {
  const a = PSEUDO_ADJECTIVES[Math.floor(Math.random() * PSEUDO_ADJECTIVES.length)];
  const b = PSEUDO_ANIMALS   [Math.floor(Math.random() * PSEUDO_ANIMALS.length)];
  return a + b;
}

function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64urlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function cleanPseudo(str) {
  return String(str).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, PSEUDO_MAX);
}

// Normalizes a relative path: no control chars, no "..", no leading slash
function cleanPath(str) {
  return String(str)
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/\\/g, '/')
    .split('/')
    .filter(part => part && part !== '.' && part !== '..')
    .join('/')
    .slice(0, 1024) || 'fichier';
}

function baseName(p) {
  return p.split('/').pop();
}

function formatSize(bytes) {
  if (bytes < 1024)               return bytes + ' o';
  if (bytes < 1024 * 1024)        return (bytes / 1024).toFixed(1) + ' Ko';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' Mo';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' Go';
}

function fileExtCategory(name) {
  const ext = name.split('.').pop().toLowerCase();
  if (['jpg','jpeg','png','gif','webp','svg','bmp','ico'].includes(ext)) return 'img';
  if (['mp4','webm','mov','avi','mkv'].includes(ext)) return 'vid';
  if (['mp3','wav','ogg','flac','aac','m4a'].includes(ext)) return 'aud';
  if (['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','md','csv'].includes(ext)) return 'doc';
  return 'other';
}

function fileEmoji(name) {
  return { img: '🖼️', vid: '🎬', aud: '🎵', doc: '📄', other: '📦' }[fileExtCategory(name)];
}

function badgeClass(name) {
  return 'badge-' + fileExtCategory(name);
}

function badgeLabel(name) {
  return { img: 'Image', vid: 'Vidéo', aud: 'Audio', doc: 'Doc', other: 'Fichier' }[fileExtCategory(name)];
}

// Extra MIME types used when handing a file to another app (system share sheet)
const SHARE_TYPES = {
  doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  odt: 'application/vnd.oasis.opendocument.text', ods: 'application/vnd.oasis.opendocument.spreadsheet',
  rtf: 'application/rtf', epub: 'application/epub+zip', zip: 'application/zip',
  rar: 'application/vnd.rar', '7z': 'application/x-7z-compressed', mkv: 'video/x-matroska', avi: 'video/x-msvideo'
};

function shareType(name) {
  const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  const preview = previewKind(name);
  if (preview) return preview.kind === 'text' ? 'text/plain' : preview.type;
  return Object.hasOwn(SHARE_TYPES, ext) ? SHARE_TYPES[ext] : 'application/octet-stream';
}

// True when the OS share sheet ("Ouvrir avec…") accepts this kind of file
function canOpenWith(name) {
  if (!navigator.canShare) return false;
  try {
    return navigator.canShare({ files: [new File([''], baseName(name), { type: shareType(name) })] });
  } catch {
    return false;
  }
}

// Returns { kind, type } when the file can be shown in the viewer, otherwise null
function previewKind(name) {
  const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  for (const [kind, types] of Object.entries(PREVIEW_TYPES)) {
    if (Object.hasOwn(types, ext)) return { kind, type: types[ext] };
  }
  return null;
}

function storageGet(store, key) {
  try { return store.getItem(key); } catch { return null; }
}

function storageSet(store, key, value) {
  try { value === null ? store.removeItem(key) : store.setItem(key, value); } catch { /* storage unavailable */ }
}

function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

let toastTimer;
// action: optional { label, onClick } rendered as a button inside the toast
function showToast(msg, duration = 3000, action = null) {
  const el = document.getElementById('toast');
  const text = document.createElement('span');
  text.textContent = msg;
  el.replaceChildren(text);
  if (action) {
    const btn = document.createElement('button');
    btn.className = 'toast-action';
    btn.textContent = action.label;
    btn.addEventListener('click', () => { el.classList.remove('show'); action.onClick(); });
    el.appendChild(btn);
  }
  el.classList.toggle('has-action', !!action);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show', 'has-action'), duration);
}

let currentScreen = null;
function showScreen(id) {
  currentScreen = id;
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.remove('active');
    s.style.display = '';
  });
  const el = document.getElementById(id);
  el.style.display = 'flex';
  // force reflow then add active for transition (unless another screen was shown meanwhile)
  requestAnimationFrame(() => { requestAnimationFrame(() => { if (currentScreen === id) el.classList.add('active'); }); });
}

function avatarInitials(pseudo) {
  const parts = pseudo.match(/[A-ZÀ-Ö][a-zà-ö]*/g);
  if (parts && parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return pseudo.slice(0, 2).toUpperCase();
}

// ── CRYPTO ────────────────────────────────────────────────────────
const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function secureContextOk() {
  if (window.isSecureContext && window.crypto?.subtle) return true;
  showToast('Le chiffrement nécessite HTTPS (ou localhost). Voir le README.', 6000);
  return false;
}

async function setSalonKey(keyB64) {
  const base = await crypto.subtle.importKey('raw', b64urlDecode(keyB64), 'HKDF', false, ['deriveKey', 'deriveBits']);
  const hkdf = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: textEnc.encode(info) });
  cryptoKey = await crypto.subtle.deriveKey(hkdf('p2pshare-enc'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  authToken = toHex(await crypto.subtle.deriveBits(hkdf('p2pshare-auth'), base, 256));
  salonKey = keyB64;
}

async function encryptBytes(plain, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, cryptoKey, plain);
  const out = new Uint8Array(IV_LEN + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), IV_LEN);
  return out;
}

function decryptBytes(bytes, aad) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, IV_LEN), additionalData: aad }, cryptoKey, bytes.subarray(IV_LEN));
}

// ── INVITES ───────────────────────────────────────────────────────
function inviteUrl() {
  return `${location.origin}/?salon=${salonId}#${salonKey}`;
}

// Accepts a full invite link or a "salonId-key" code
function parseInvite(input) {
  const str = String(input || '').trim();
  let sid, key;
  if (str.includes('salon=')) {
    try {
      const url = new URL(str, location.origin);
      sid = url.searchParams.get('salon');
      key = url.hash.slice(1);
    } catch { return null; }
  } else {
    const m = str.match(/^([0-9a-fA-F]{8})-([A-Za-z0-9_-]{22})$/);
    if (m) { sid = m[1]; key = m[2]; }
  }
  sid = sid && sid.toLowerCase();
  return SALON_RE.test(sid) && KEY_RE.test(key) ? { salonId: sid, key } : null;
}


// ── DOM REFS ──────────────────────────────────────────────────────
const pseudoDisplay    = document.getElementById('pseudo-display');
const btnRefreshPseudo = document.getElementById('btn-refresh-pseudo');
const btnCreate        = document.getElementById('btn-create');
const joinCodeInput    = document.getElementById('join-code');
const btnJoin          = document.getElementById('btn-join');
const btnLeave         = document.getElementById('btn-leave');
const btnHome          = document.getElementById('btn-home');
const btnCopy          = document.getElementById('btn-copy');
const btnZip           = document.getElementById('btn-zip');
const btnAddFiles      = document.getElementById('btn-add-files');
const btnAddFolder     = document.getElementById('btn-add-folder');
const fileInput        = document.getElementById('file-input');
const folderInput      = document.getElementById('folder-input');
const membersList      = document.getElementById('members-list');
const memberCount      = document.getElementById('member-count');
const filesList        = document.getElementById('files-list');
const dropZone         = document.getElementById('drop-zone');
const emptyState       = document.getElementById('empty-state');
const filesCount       = document.getElementById('files-count');
const qrBox            = document.getElementById('qr-code');
const linkDisplay      = document.getElementById('link-display');
const sidebarSalonId   = document.getElementById('sidebar-salon-id');
const loadingText      = document.getElementById('loading-text');
const zipButtonHtml    = btnZip.innerHTML;
const sidebar          = document.getElementById('sidebar');
const memberCountMobile = document.getElementById('member-count-mobile');
const btnScan          = document.getElementById('btn-scan');
const btnInstall       = document.getElementById('btn-install');
const scanner          = document.getElementById('scanner');
const scannerVideo     = document.getElementById('scanner-video');
const scannerHint      = document.getElementById('scanner-hint');
const viewerShare      = document.getElementById('viewer-share');
const viewer           = document.getElementById('viewer');
const viewerTitle      = document.getElementById('viewer-title');
const viewerBody       = document.getElementById('viewer-body');
const viewerTab        = document.getElementById('viewer-tab');
const viewerSave       = document.getElementById('viewer-save');
const viewerClose      = document.getElementById('viewer-close');

// ── PSEUDO ────────────────────────────────────────────────────────
function setPseudo(p) {
  myPseudo = p;
  pseudoDisplay.textContent = p;
  storageSet(localStorage, PSEUDO_KEY, p);
}

function initPseudo() {
  setPseudo(cleanPseudo(storageGet(localStorage, PSEUDO_KEY) || '') || randomPseudo());
}

function readPseudoInput() {
  const p = cleanPseudo(pseudoDisplay.textContent);
  setPseudo(p || myPseudo);
}

pseudoDisplay.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); pseudoDisplay.blur(); }
});
pseudoDisplay.addEventListener('input', () => {
  if (pseudoDisplay.textContent.length > PSEUDO_MAX) {
    pseudoDisplay.textContent = pseudoDisplay.textContent.slice(0, PSEUDO_MAX);
  }
});
pseudoDisplay.addEventListener('blur', readPseudoInput);
btnRefreshPseudo.addEventListener('click', () => setPseudo(randomPseudo()));

// ── SOCKET ────────────────────────────────────────────────────────
function initSocket() {
  socket = io({ transports: ['websocket', 'polling'] });
  let wasConnected = false;

  socket.on('connect', () => {
    if (wasConnected && salonId) resumeAfterReconnect();
    wasConnected = true;
  });

  socket.on('disconnect', (reason) => {
    // When the screen is off we keep our place in the salon: no need to warn
    if (salonId && reason !== 'io client disconnect' && document.visibilityState === 'visible') {
      showToast('Connexion perdue, reconnexion…', 4000);
    }
  });

  // The same session was resumed elsewhere (duplicated tab, other device)
  socket.on('session-replaced', () => {
    resetSalon();
    saveSession(null);
    history.replaceState(null, '', '/');
    document.getElementById('destroyed-msg').textContent = 'Cette session a été reprise dans un autre onglet ou sur un autre appareil.';
    showScreen('screen-destroyed');
  });

  socket.on('member-joined', ({ memberId, pseudo, isHost: host }) => {
    if (!salonId) return;
    addMember(memberId, pseudo, host, null, false);
    showToast(`${pseudo} a rejoint le salon.`);
    for (const fileId of myFiles.keys()) announceFile(fileId, memberId);
  });

  socket.on('member-away', ({ memberId, graceMs }) => {
    const m = members.get(memberId);
    if (!m) return;
    setMemberAway(memberId, true);
    if (m.isHost) {
      showToast(`${m.pseudo} (hôte) est en veille. Le salon fermera dans ${Math.round(graceMs / 60_000)} min s'il ne revient pas.`, 6000);
    }
  });

  socket.on('member-back', ({ memberId, pseudo, isHost: host }) => {
    if (!salonId) return;
    if (members.has(memberId)) {
      setMemberPseudo(memberId, pseudo);
      setMemberAway(memberId, false);
    } else {
      addMember(memberId, pseudo, host, null, false);
    }
    // Their page may have been reloaded: make sure they know our files
    for (const fileId of myFiles.keys()) announceFile(fileId, memberId);
  });

  socket.on('peer-registered', ({ memberId, peerId }) => {
    const m = members.get(memberId);
    if (!m) return;
    if (m.peerId !== peerId) closeConn(memberId);
    m.peerId = peerId;
    maybeConnect(memberId);
  });

  socket.on('member-left', ({ memberId, pseudo }) => {
    if (!members.has(memberId)) return;
    removeMember(memberId);
    showToast(`${pseudo} a quitté le salon.`);
  });

  socket.on('file-announce', (p) => { onFileAnnounced(p).catch(err => console.warn('file-announce:', err)); });

  socket.on('file-remove', ({ from, fileId }) => {
    const info = remoteFiles.get(fileId);
    if (!info || info.senderMemberId !== from) return;
    removeRemoteFile(fileId);
  });

  // A member lists the files it still has (after a reload): drop the others
  socket.on('file-sync', ({ from, fileIds }) => {
    const keep = new Set(fileIds);
    for (const [fileId, info] of [...remoteFiles]) {
      if (info.senderMemberId === from && !keep.has(fileId)) removeRemoteFile(fileId);
    }
  });

  socket.on('salon-destroyed', ({ reason }) => {
    resetSalon();
    saveSession(null);
    history.replaceState(null, '', '/');
    document.getElementById('destroyed-msg').textContent = reason;
    showScreen('screen-destroyed');
  });

  // Relay fallback (same messages as the P2P channel, forwarded by the server)
  socket.on('relay-ctrl', ({ from, msg }) => handleCtrl(from, msg, 'relay'));
  socket.on('relay-chunk', ({ from, data }, cb) => {
    handleChunk(from, data).then(() => cb?.({ ok: true }), () => cb?.({ ok: false }));
  });
}

function waitConnected(timeoutMs = 10_000) {
  if (socket.connected) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.off('connect', onConnect); reject(new Error('Serveur injoignable.')); }, timeoutMs);
    function onConnect() { clearTimeout(timer); resolve(); }
    socket.once('connect', onConnect);
  });
}

async function emitAck(event, data) {
  await waitConnected();
  return socket.timeout(10_000).emitWithAck(event, data);
}

// Coming back to the page (screen unlocked, app reopened): reconnect right away
// instead of waiting for Socket.io's reconnection backoff
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible' || !salonId) return;
  if (!socket.connected) socket.connect();
  if (peer && !peer.destroyed && peer.disconnected) peer.reconnect();
  updateWakeLock();   // the browser drops the wake lock whenever the page is hidden
});

// ── SCREEN WAKE LOCK ──────────────────────────────────────────────
// Mobile browsers freeze the page when the screen turns off, which kills transfers:
// keep the screen on while anything is being sent or received.
let wakeLock = null;
let wakeLockPending = false;

async function updateWakeLock() {
  const busy = uploads.size > 0 || downloads.size > 0;
  if (!('wakeLock' in navigator)) return;
  if (busy && !wakeLock && !wakeLockPending && document.visibilityState === 'visible') {
    wakeLockPending = true;
    try {
      wakeLock = await navigator.wakeLock.request('screen');
      wakeLock.addEventListener('release', () => { wakeLock = null; });
    } catch { /* refused (battery saver…): transfers still work, the screen may just turn off */ }
    wakeLockPending = false;
    if (!(uploads.size > 0 || downloads.size > 0)) updateWakeLock();   // finished meanwhile
  } else if (!busy && wakeLock) {
    const lock = wakeLock;
    wakeLock = null;
    lock.release().catch(() => {});
  }
}

// ── SESSION ───────────────────────────────────────────────────────
// Kept per tab so a reload (or the phone killing the tab) resumes the same membership
function getSession() {
  try { return JSON.parse(storageGet(sessionStorage, SESSION_KEY)); } catch { return null; }
}

function saveSession(session) {
  storageSet(sessionStorage, SESSION_KEY, session ? JSON.stringify(session) : null);
}

function startSession(res) {
  myMemberId = res.memberId;
  sessionToken = res.token;
  saveSession({ salonId: res.salonId, memberId: res.memberId, token: res.token, key: salonKey });
}

// ── ENTER / LEAVE SALON ───────────────────────────────────────────
async function createSalon() {
  readPseudoInput();
  if (!secureContextOk()) return;
  showScreen('screen-loading');
  loadingText.textContent = 'Création du salon…';
  try {
    await setSalonKey(b64urlEncode(crypto.getRandomValues(new Uint8Array(16))));
    const res = await emitAck('create-salon', { pseudo: myPseudo, auth: authToken });
    if (!res?.ok) throw new Error(res?.error || 'Création impossible.');
    startSession(res);
    enterSalon(res.salonId, true, res.members);
  } catch (err) {
    failToHome(err);
  }
}

async function joinSalon(invite, { fromLink = false } = {}) {
  readPseudoInput();
  joinCodeInput.value = `${location.origin}/?salon=${invite.salonId}#${invite.key}`;
  if (!secureContextOk()) return;
  showScreen('screen-loading');
  loadingText.textContent = 'Connexion au salon…';
  try {
    await setSalonKey(invite.key);
    const res = await emitAck('join-salon', { salonId: invite.salonId, pseudo: myPseudo, auth: authToken });
    if (!res?.ok) throw new Error(res?.error || 'Connexion impossible.');
    startSession(res);
    enterSalon(res.salonId, false, res.members);
    if (res.hostAway) showToast('L\'hôte est momentanément en veille.', 5000);
  } catch (err) {
    // A dead invite link must not retry on every page reload
    if (fromLink) history.replaceState(null, '', '/');
    failToHome(err);
  }
}

// Page (re)loaded with a saved session: take our place back
async function resumeSession(session) {
  if (!secureContextOk()) return;
  showScreen('screen-loading');
  loadingText.textContent = 'Reprise de la session…';
  let res;
  try {
    await setSalonKey(session.key);
    res = await emitAck('resume-session', { salonId: session.salonId, memberId: session.memberId, token: session.token, pseudo: myPseudo });
  } catch (err) {
    failToHome(err);   // server unreachable: keep the session, a reload will retry
    return;
  }
  if (!res?.ok) {
    // Our place expired, but the salon may still exist: come back as a new member
    saveSession(null);
    joinSalon({ salonId: session.salonId, key: session.key }, { fromLink: true });
    return;
  }
  myMemberId = res.memberId;
  sessionToken = session.token;
  enterSalon(res.salonId, res.isHost, res.members);
  socket.emit('file-sync', { fileIds: [] });   // files shared before the reload are gone
}

// Socket reconnected (screen unlocked, network back): same member, same files
async function resumeAfterReconnect() {
  let res;
  try {
    res = await emitAck('resume-session', { salonId, memberId: myMemberId, token: sessionToken, pseudo: myPseudo });
  } catch {
    return;   // connection dropped again: the next 'connect' retries
  }
  if (!salonId) return;   // left in the meantime
  if (!res?.ok) {
    // Away for too long: our place was released. Try to rejoin as a new member.
    const invite = { salonId, key: salonKey };
    resetSalon();
    saveSession(null);
    showToast('Votre session a expiré, reconnexion au salon…', 4000);
    joinSalon(invite, { fromLink: true });
    return;
  }
  isHost = res.isHost;
  // P2P links did not survive the sleep: rebuild them
  for (const id of members.keys()) closeConn(id);
  syncMembers(res.members);
  registerPeer();
  socket.emit('file-sync', { fileIds: [...myFiles.keys()] });
}

function failToHome(err) {
  cryptoKey = null; authToken = null; salonKey = null;
  showToast('Erreur : ' + (err?.message || err), 5000);
  showScreen('screen-home');
}

function enterSalon(sid, host, memberInfos) {
  salonId = sid;
  isHost = host;

  members.clear();
  membersList.innerHTML = '';
  filesList.innerHTML = '';
  myFiles.clear();
  remoteFiles.clear();

  addMemberUI(myMemberId, myPseudo, host, true);
  for (const m of memberInfos) addMember(m.memberId, m.pseudo, m.isHost, m.peerId, m.away);

  const url = inviteUrl();
  history.replaceState(null, '', url);
  qrBox.innerHTML = '';
  new QRCode(qrBox, { text: url, width: 128, height: 128, colorDark: '#000', colorLight: '#fff' });
  linkDisplay.textContent = url;
  sidebarSalonId.textContent = sid;

  updateFilesUI();
  showScreen('screen-salon');
  initPeer().catch(err => console.warn('PeerJS init failed, relay only:', err));
}

function resetSalon() {
  closeViewer();
  setMobilePanel(null);
  localCopies.clear();
  for (const url of tabUrls) URL.revokeObjectURL(url);
  tabUrls.clear();
  for (const d of [...downloads.values()]) failDownload(d, 'Salon fermé.', { silent: true });
  for (const up of uploads.values()) up.cancelled = true;
  for (const id of [...members.keys()]) closeConn(id);
  if (peer) { try { peer.destroy(); } catch { /* already destroyed */ } peer = null; }
  salonId = null; salonKey = null; cryptoKey = null; authToken = null; isHost = false;
  myMemberId = null; sessionToken = null;
  members.clear(); myFiles.clear(); remoteFiles.clear();
  membersList.innerHTML = '';
  filesList.innerHTML = '';
}

function leaveSalon() {
  socket.emit('leave-salon');
  resetSalon();
  saveSession(null);
  history.replaceState(null, '', '/');
  showScreen('screen-home');
}

// ── MEMBERS ───────────────────────────────────────────────────────
function addMember(memberId, pseudo, host, peerId, away) {
  if (members.has(memberId)) removeMember(memberId);
  members.set(memberId, { pseudo, isHost: host, peerId, away: !!away, conn: null, retries: 0, retryTimer: null });
  addMemberUI(memberId, pseudo, host, false);
  setMemberAway(memberId, !!away);
  maybeConnect(memberId);
}

// Brings the local member list in line with the server's after a reconnection
function syncMembers(list) {
  const fresh = new Map(list.map(m => [m.memberId, m]));
  for (const id of [...members.keys()]) if (!fresh.has(id)) removeMember(id);
  for (const m of list) {
    const cur = members.get(m.memberId);
    if (!cur) {
      addMember(m.memberId, m.pseudo, m.isHost, m.peerId, m.away);
    } else {
      cur.peerId = m.peerId;
      setMemberPseudo(m.memberId, m.pseudo);
      setMemberAway(m.memberId, m.away);
    }
  }
}

// An away member keeps its place and its files, but can't send or receive until it's back
function setMemberAway(memberId, away) {
  const m = members.get(memberId);
  if (!m) return;
  m.away = away;
  if (away) {
    closeConn(memberId);
    for (const d of [...downloads.values()]) if (d.from === memberId) failDownload(d, `${m.pseudo} est passé en veille.`);
    for (const up of uploads.values()) if (up.to === memberId) up.cancelled = true;
  } else {
    m.retries = 0;
    maybeConnect(memberId);
  }
  const li = document.getElementById('member-' + memberId);
  if (li) {
    li.classList.toggle('away', away);
    const dot = li.querySelector('.member-online');
    if (away) dot.title = 'En veille (écran verrouillé ou connexion coupée)';
    else setMemberLinkUI(memberId, !!m.conn?.open);
  }
}

function setMemberPseudo(memberId, pseudo) {
  const m = members.get(memberId);
  if (!m || !pseudo) return;
  m.pseudo = pseudo;
  const name = document.querySelector(`#member-${CSS.escape(memberId)} .member-name`);
  if (name) name.textContent = pseudo;
}

function removeMember(memberId) {
  closeConn(memberId);
  members.delete(memberId);
  removeMemberUI(memberId);
  for (const d of [...downloads.values()]) if (d.from === memberId) failDownload(d, 'L\'expéditeur a quitté le salon.');
  for (const up of uploads.values()) if (up.to === memberId) up.cancelled = true;
  for (const [fid, info] of [...remoteFiles]) if (info.senderMemberId === memberId) removeRemoteFile(fid);
}

function addMemberUI(memberId, pseudo, isHostMember, isMe) {
  const li = document.createElement('li');
  li.className = 'member-item';
  li.id = 'member-' + memberId;
  const idx = membersList.children.length % AVATAR_CLASSES.length;
  li.innerHTML = `
    <div class="member-avatar ${AVATAR_CLASSES[idx]}">${escapeHtml(avatarInitials(pseudo))}</div>
    <span class="member-name">${escapeHtml(pseudo)}</span>
    ${isMe ? '<span class="member-you">(vous)</span>' : '<span class="member-away">en veille</span>'}
    ${isHostMember ? '<span class="member-host-badge">hôte</span>' : ''}
    <div class="member-online${isMe ? '' : ' relay'}" title="${isMe ? 'Vous' : 'Via le relais du serveur (chiffré)'}"></div>
  `;
  membersList.appendChild(li);
  updateMemberCount();
}

function setMemberLinkUI(memberId, direct) {
  const dot = document.querySelector(`#member-${CSS.escape(memberId)} .member-online`);
  if (!dot) return;
  dot.title = direct ? 'Connexion P2P directe' : 'Via le relais du serveur (chiffré)';
  dot.classList.toggle('relay', !direct);
}

function removeMemberUI(memberId) {
  document.getElementById('member-' + memberId)?.remove();
  updateMemberCount();
}

function updateMemberCount() {
  const count = membersList.querySelectorAll('.member-item').length;
  memberCount.textContent = count;
  memberCountMobile.textContent = count;
}

// ── PEER (WebRTC) ─────────────────────────────────────────────────
async function initPeer() {
  if (peer && !peer.destroyed) { registerPeer(); return; }
  if (!iceServers) {
    try { iceServers = (await (await fetch('/config')).json()).iceServers; }
    catch { iceServers = [{ urls: 'stun:stun.l.google.com:19302' }]; }
  }
  if (!salonId || peer) return;

  const secure = location.protocol === 'https:';
  peer = new Peer({
    host: location.hostname,
    port: Number(location.port) || (secure ? 443 : 80),
    path: '/peerjs',
    secure,
    config: { iceServers },
    debug: 0
  });
  const current = peer;

  peer.on('open', registerPeer);
  peer.on('connection', onIncomingConnection);
  peer.on('disconnected', () => {
    setTimeout(() => { if (peer === current && !current.destroyed) current.reconnect(); }, 2000);
  });
  peer.on('error', (err) => {
    console.warn('PeerJS error:', err.type, err.message);
    // Our peer id was released while the phone slept: start over with a new one
    if (peer === current && ['unavailable-id', 'invalid-id'].includes(err.type)) {
      try { current.destroy(); } catch { /* already destroyed */ }
      peer = null;
      setTimeout(() => { if (salonId && !peer) initPeer().catch(() => {}); }, 1000);
    }
  });
}

function registerPeer() {
  if (!salonId || !peer?.open) return;
  socket.emit('register-peer', { peerId: peer.id });
  for (const sid of members.keys()) maybeConnect(sid);
}

// Exactly one side initiates: the one with the smaller peer id
function maybeConnect(memberId) {
  const m = members.get(memberId);
  if (!m || m.away || !m.peerId || !peer?.open || m.conn || m.retryTimer) return;
  if (peer.id > m.peerId) return;
  const conn = peer.connect(m.peerId, { reliable: true, serialization: 'raw', metadata: { memberId: myMemberId } });
  attachConn(memberId, conn);
}

function onIncomingConnection(conn) {
  const memberId = conn.metadata?.memberId;
  const m = members.get(memberId);
  if (!m || (m.peerId && m.peerId !== conn.peer) || conn.serialization !== 'raw') {
    conn.close();
    return;
  }
  m.peerId = conn.peer;
  if (m.conn && m.conn !== conn) closeConn(memberId);
  attachConn(memberId, conn);
}

function attachConn(memberId, conn) {
  const m = members.get(memberId);
  m.conn = conn;
  conn.on('open', () => {
    if (m.conn !== conn) return;
    m.retries = 0;
    setMemberLinkUI(memberId, true);
  });
  conn.on('data', (data) => onPeerData(memberId, data));
  conn.on('close', () => onConnLost(memberId, conn));
  conn.on('error', (err) => { console.warn('DataConnection error:', err.type || err); onConnLost(memberId, conn); });
}

function closeConn(memberId) {
  const m = members.get(memberId);
  if (!m) return;
  clearTimeout(m.retryTimer);
  m.retryTimer = null;
  const conn = m.conn;
  m.conn = null;
  if (conn) { try { conn.close(); } catch { /* already closed */ } }
}

function onConnLost(memberId, conn) {
  const m = members.get(memberId);
  if (!m || m.conn !== conn) return;
  m.conn = null;
  setMemberLinkUI(memberId, false);
  for (const d of [...downloads.values()]) {
    if (d.from === memberId && d.via === 'p2p') failDownload(d, 'Connexion P2P perdue.');
  }
  // Only the initiator retries, with backoff
  if (peer?.open && m.peerId && peer.id < m.peerId && m.retries < 3) {
    const delay = 2000 * 2 ** m.retries++;
    m.retryTimer = setTimeout(() => { m.retryTimer = null; maybeConnect(memberId); }, delay);
  }
}

function onPeerData(memberId, data) {
  if (typeof data === 'string') {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    handleCtrl(memberId, msg, 'p2p');
  } else if (data instanceof ArrayBuffer) {
    handleChunk(memberId, data).catch(() => {});
  }
}

function p2pOpen(memberId) {
  return !!members.get(memberId)?.conn?.open;
}

// ── TRANSPORT ─────────────────────────────────────────────────────
function sendCtrl(to, via, msg) {
  if (via === 'p2p') {
    const conn = members.get(to)?.conn;
    if (!conn?.open) throw new Error('Connexion P2P perdue.');
    conn.send(JSON.stringify(msg));
  } else {
    socket.emit('relay-ctrl', { to, msg });
  }
}

function trySendCtrl(to, via, msg) {
  try { sendCtrl(to, via, msg); } catch { /* peer gone */ }
}

function waitDrain(dc) {
  return new Promise((resolve) => {
    dc.bufferedAmountLowThreshold = P2P_HIGH_WATER / 2;
    const timer = setTimeout(done, 100);
    function done() { clearTimeout(timer); dc.removeEventListener('bufferedamountlow', done); resolve(); }
    dc.addEventListener('bufferedamountlow', done);
  });
}

// Chunk senders apply backpressure so a large file is never fully buffered in memory
function p2pChunkSender(to) {
  const conn = members.get(to)?.conn;
  return {
    async send(buf) {
      if (!conn?.open || members.get(to)?.conn !== conn) throw new Error('Connexion P2P perdue.');
      conn.send(buf);
      while (conn.open && (conn.dataChannel.bufferedAmount > P2P_HIGH_WATER || conn.bufferSize > 0)) {
        await waitDrain(conn.dataChannel);
      }
    },
    async flush() {}
  };
}

function relayChunkSender(to) {
  const pending = [];
  const check = (res) => { if (!res?.ok) throw new Error(res?.error === 'rate' ? 'Limite du relais atteinte.' : 'Relais interrompu.'); };
  return {
    async send(buf) {
      if (pending.length >= RELAY_WINDOW) check(await pending.shift());
      pending.push(socket.timeout(35_000).emitWithAck('relay-chunk', { to, data: buf }).catch(() => ({ ok: false })));
    },
    async flush() {
      while (pending.length) check(await pending.shift());
    }
  };
}

// Chunk layout: [16 bytes transferId][uint32 index][12 bytes IV][AES-GCM ciphertext]
// The 20-byte tag is authenticated as AAD, so chunks cannot be swapped or reordered.
function makeTag(transferId, index) {
  const tag = new Uint8Array(TAG_LEN);
  tag.set(textEnc.encode(transferId));
  new DataView(tag.buffer).setUint32(16, index);
  return tag;
}

// ── CONTROL MESSAGES ──────────────────────────────────────────────
// req (receiver → sender), start / done / err (sender → receiver), cancel (receiver → sender)
function handleCtrl(from, msg, via) {
  if (!salonId || !members.has(from) || !msg || typeof msg !== 'object' || !ID_RE.test(msg.tid)) return;
  const d = downloads.get(msg.tid);

  switch (msg.t) {
    case 'req':
      if (ID_RE.test(msg.fid)) sendFile(from, via, msg.tid, msg.fid);
      break;

    case 'start':
      if (!d || d.from !== from || d.chunks !== null) return;
      if (!Number.isSafeInteger(msg.size) || msg.size < 0 || msg.chunks !== Math.ceil(msg.size / CHUNK_SIZE)) {
        failDownload(d, 'Réponse invalide de l\'expéditeur.');
        return;
      }
      d.size = msg.size;
      d.chunks = msg.chunks;
      armTimeout(d);
      break;

    case 'done':
      if (!d || d.from !== from) return;
      d.queue = d.queue.then(() => finishDownload(d)).catch(err => failDownload(d, err.message));
      break;

    case 'err':
      if (d && d.from === from) failDownload(d, 'Transfert interrompu par l\'expéditeur.');
      break;

    case 'cancel': {
      const up = uploads.get(msg.tid);
      if (up && up.to === from) up.cancelled = true;
      break;
    }
  }
}

// ── SEND FILE ─────────────────────────────────────────────────────
async function sendFile(to, via, transferId, fileId) {
  const fd = myFiles.get(fileId);
  if (!fd || uploads.has(transferId)) {
    trySendCtrl(to, via, { t: 'err', tid: transferId });
    return;
  }
  const up = { fileId, to, via, pseudo: members.get(to)?.pseudo || '?', pct: 0, cancelled: false };
  uploads.set(transferId, up);
  updateWakeLock();
  renderUploadStatus(fileId);

  try {
    const file = fd.file;
    const total = Math.ceil(file.size / CHUNK_SIZE);
    const sender = via === 'p2p' ? p2pChunkSender(to) : relayChunkSender(to);
    sendCtrl(to, via, { t: 'start', tid: transferId, size: file.size, chunks: total });

    for (let i = 0; i < total; i++) {
      if (up.cancelled) throw new Error('Annulé.');
      if (!myFiles.has(fileId)) throw new Error('Fichier retiré.');
      const plain = await file.slice(i * CHUNK_SIZE, Math.min(file.size, (i + 1) * CHUNK_SIZE)).arrayBuffer();
      const tag = makeTag(transferId, i);
      const enc = await encryptBytes(plain, tag);
      const packet = new Uint8Array(TAG_LEN + enc.length);
      packet.set(tag);
      packet.set(enc, TAG_LEN);
      await sender.send(packet.buffer);
      up.pct = Math.round(((i + 1) / total) * 100);
      renderUploadStatus(fileId);
    }
    await sender.flush();
    sendCtrl(to, via, { t: 'done', tid: transferId });
  } catch (err) {
    console.warn('Upload failed:', err.message);
    if (!up.cancelled) trySendCtrl(to, via, { t: 'err', tid: transferId });
  } finally {
    uploads.delete(transferId);
    updateWakeLock();
    renderUploadStatus(fileId);
  }
}

// ── RECEIVE FILE ──────────────────────────────────────────────────
function memorySink() {
  const parts = [];
  return {
    write(bytes) { parts.push(bytes); },
    async close(type) { return new Blob(parts, { type }); },
    abort() { parts.length = 0; }
  };
}

async function diskSink(handle) {
  const writable = await handle.createWritable();
  return {
    handle,
    write(bytes) { return writable.write(bytes); },
    async close() { await writable.close(); return null; },
    abort() { writable.abort().catch(() => {}); }
  };
}

function activeDownloadFor(fileId) {
  for (const d of downloads.values()) if (d.fileId === fileId) return d;
  return null;
}

// Resolves with a Blob when toMemory is true, otherwise saves the file and resolves with null
async function startDownload(fileId, { toMemory = false, doneText = 'Téléchargé ✓' } = {}) {
  const info = remoteFiles.get(fileId);
  if (!info || !members.has(info.senderMemberId)) throw new Error('Fichier indisponible.');
  const sender = members.get(info.senderMemberId);
  if (sender.away) throw new Error(`${sender.pseudo} est en veille : réessayez quand il sera de retour.`);
  if (activeDownloadFor(fileId)) throw new Error('Téléchargement déjà en cours.');

  let sink = null;
  if (!toMemory && window.showSaveFilePicker) {
    // Stream straight to disk: large files never sit in RAM
    try {
      sink = await diskSink(await window.showSaveFilePicker({ suggestedName: baseName(info.name) }));
    } catch (err) {
      if (err.name === 'AbortError') return null;
    }
  }
  if (!sink) {
    sink = memorySink();
    if (!toMemory && info.size > 1024 ** 3) showToast('Fichier volumineux : votre navigateur doit le garder en mémoire.', 5000);
  }

  const via = p2pOpen(info.senderMemberId) ? 'p2p' : 'relay';
  const transferId = randomHex(8);

  return new Promise((resolve, reject) => {
    const d = {
      transferId, fileId, from: info.senderMemberId, via, sink, toMemory, doneText,
      size: null, chunks: null, next: 0, bytes: 0, failed: false,
      queue: Promise.resolve(), timer: null, resolve, reject
    };
    downloads.set(transferId, d);
    updateWakeLock();
    armTimeout(d);
    setDownloadUI(fileId, 'active', via === 'relay' ? 'Via relais…' : 'Téléchargement…');
    try {
      sendCtrl(d.from, via, { t: 'req', tid: transferId, fid: fileId });
    } catch (err) {
      failDownload(d, err.message);
    }
  });
}

function handleChunk(from, buf) {
  if (!(buf instanceof ArrayBuffer) || buf.byteLength < TAG_LEN + IV_LEN + 16) return Promise.resolve();
  const tag = new Uint8Array(buf, 0, TAG_LEN);
  const d = downloads.get(textDec.decode(tag.subarray(0, 16)));
  if (!d || d.from !== from) return Promise.resolve();
  const index = new DataView(buf).getUint32(16);

  d.queue = d.queue.then(async () => {
    if (d.failed) return;
    if (d.chunks === null || index !== d.next || index >= d.chunks) throw new Error('Données hors séquence.');
    let plain;
    try {
      plain = new Uint8Array(await decryptBytes(new Uint8Array(buf, TAG_LEN), tag));
    } catch {
      throw new Error('Données corrompues ou clé invalide.');
    }
    await d.sink.write(plain);
    d.next++;
    d.bytes += plain.byteLength;
    if (d.bytes > d.size) throw new Error('Taille incohérente.');
    armTimeout(d);
    updateDownloadProgress(d.fileId, d.bytes, d.size);
  }).catch(err => failDownload(d, err.message));
  return d.queue;
}

async function finishDownload(d) {
  if (d.failed) return;
  if (d.chunks === null || d.next !== d.chunks || d.bytes !== d.size) throw new Error('Fichier incomplet.');
  clearTimeout(d.timer);
  downloads.delete(d.transferId);
  updateWakeLock();
  const info = remoteFiles.get(d.fileId);
  const blob = await d.sink.close('application/octet-stream');
  if (blob && !d.toMemory) saveBlob(blob, baseName(info?.name || 'fichier'));
  // Keep a copy that can be opened again without a new transfer
  const openable = info && (previewKind(info.name) || canOpenWith(info.name));
  if (openable && (d.sink.handle || blob.size <= PREVIEW_MAX_BYTES)) {
    localCopies.set(d.fileId, d.sink.handle || blob);
  }
  setDownloadUI(d.fileId, 'done', d.doneText);
  updatePreviewButton(d.fileId);
  if (!d.toMemory && info) {
    const fileId = d.fileId;
    showToast(`« ${baseName(info.name)} » téléchargé.`, 6000,
      canOpen(fileId) ? { label: 'Ouvrir', onClick: () => openFile(fileId) } : null);
  }
  d.resolve(blob);
}

function failDownload(d, reason, { silent = false } = {}) {
  if (d.failed) return;
  d.failed = true;
  clearTimeout(d.timer);
  downloads.delete(d.transferId);
  updateWakeLock();
  try { d.sink.abort(); } catch { /* ignore */ }
  trySendCtrl(d.from, d.via, { t: 'cancel', tid: d.transferId });
  if (!silent) {
    setDownloadUI(d.fileId, 'error', 'Échec — ' + reason);
    if (!d.toMemory) showToast('Téléchargement échoué : ' + reason, 5000);
  }
  d.reject(new Error(reason));
}

function armTimeout(d) {
  clearTimeout(d.timer);
  d.timer = setTimeout(() => failDownload(d, 'Délai dépassé.'), TRANSFER_IDLE_MS);
}

// ── FILES ─────────────────────────────────────────────────────────
async function announceFile(fileId, to) {
  const fd = myFiles.get(fileId);
  if (!fd || !cryptoKey) return;
  const plain = textEnc.encode(JSON.stringify({ name: fd.name, size: fd.size, type: fd.mimeType }));
  const meta = await encryptBytes(plain, textEnc.encode('meta:' + fileId));
  socket.emit('file-announce', to ? { fileId, meta: meta.buffer, to } : { fileId, meta: meta.buffer });
}

async function onFileAnnounced({ from, fileId, meta }) {
  const sender = members.get(from);
  if (!sender || !cryptoKey || !ID_RE.test(fileId) || !(meta instanceof ArrayBuffer)) return;
  const existing = remoteFiles.get(fileId);
  if (existing && existing.senderMemberId !== from) return;

  const plain = await decryptBytes(new Uint8Array(meta), textEnc.encode('meta:' + fileId));
  const obj = JSON.parse(textDec.decode(plain));
  if (!Number.isSafeInteger(obj.size) || obj.size < 0 || typeof obj.name !== 'string') return;
  if (!members.has(from)) return;

  const info = {
    fileId,
    name: cleanPath(obj.name),
    size: obj.size,
    mimeType: typeof obj.type === 'string' ? obj.type.slice(0, 128) : '',
    senderMemberId: from,
    senderPseudo: sender.pseudo
  };
  remoteFiles.set(fileId, info);
  if (!existing) renderRemoteFileCard(info);
  updateFilesUI();
}

// entries: [{ file, path }]
function addFiles(entries) {
  if (!salonId) return;
  for (const { file, path } of entries) {
    const fileId = randomHex(8);
    myFiles.set(fileId, { file, name: cleanPath(path || file.name), size: file.size, mimeType: file.type });
    renderMyFileCard(fileId);
    announceFile(fileId).catch(err => console.warn('announce:', err));
  }
  updateFilesUI();
}

function removeMyFile(fileId) {
  if (viewerFileId === fileId) closeViewer();
  myFiles.delete(fileId);
  for (const up of uploads.values()) if (up.fileId === fileId) up.cancelled = true;
  removeFileCard(fileId);
  socket.emit('file-remove', { fileId });
  updateFilesUI();
}

function removeRemoteFile(fileId) {
  const d = activeDownloadFor(fileId);
  if (d) failDownload(d, 'Fichier retiré par l\'expéditeur.');
  if (viewerFileId === fileId) closeViewer();
  localCopies.delete(fileId);
  remoteFiles.delete(fileId);
  removeFileCard(fileId);
  updateFilesUI();
}

// Recursively collects dropped files, keeping folder structure
async function collectDropped(dataTransfer) {
  const entries = [...dataTransfer.items].map(item => item.webkitGetAsEntry?.()).filter(Boolean);
  if (!entries.length) return [...dataTransfer.files].map(file => ({ file, path: file.name }));

  const out = [];
  async function walk(entry) {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      out.push({ file, path: entry.fullPath.replace(/^\//, '') });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      let batch;
      do {
        batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        for (const child of batch) await walk(child);
      } while (batch.length);
    }
  }
  for (const entry of entries) await walk(entry);
  return out;
}

// ── FILE CARDS ────────────────────────────────────────────────────
const ICON_REMOVE = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
const ICON_EYE = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
const ICON_DOWNLOAD = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';

function fileCardHtml(fileId, name, size, senderLabel, status, actionHtml) {
  return `
    <div class="file-thumb">${fileEmoji(name)}</div>
    <div class="file-info">
      <div class="file-name" title="${escapeHtml(name)}">${escapeHtml(name)}</div>
      <div class="file-meta">
        <span>${formatSize(size)}</span>
        <span class="file-sender">${escapeHtml(senderLabel)}</span>
        <span id="status-${fileId}">${status}</span>
      </div>
      <div class="file-progress" id="prog-wrap-${fileId}" style="display:none">
        <div class="progress-track"><div class="progress-bar-fill" id="prog-${fileId}" style="width:0%"></div></div>
        <div class="progress-label" id="prog-label-${fileId}"></div>
      </div>
    </div>
    <div class="file-actions">
      <span class="file-type-badge ${badgeClass(name)}">${badgeLabel(name)}</span>
      ${actionHtml}
    </div>
  `;
}

function previewButtonHtml(fileId) {
  return `<button class="btn-preview" id="pv-${fileId}" hidden>${ICON_EYE} <span>Aperçu</span></button>`;
}

function canOpen(fileId) {
  const info = myFiles.get(fileId) || remoteFiles.get(fileId);
  if (!info) return false;
  if (previewKind(info.name)) return true;
  return !myFiles.has(fileId) && localCopies.has(fileId) && canOpenWith(info.name);
}

// "Aperçu" fetches the file first; "Ouvrir" uses a copy that is already on this device.
// Non-previewable files get "Ouvrir" (share sheet) once downloaded, where supported.
function updatePreviewButton(fileId) {
  const btn = document.getElementById('pv-' + fileId);
  const info = myFiles.get(fileId) || remoteFiles.get(fileId);
  if (!btn || !info) return;
  const local = myFiles.has(fileId) || localCopies.has(fileId);
  const label = local ? 'Ouvrir' : 'Aperçu';
  btn.hidden = !canOpen(fileId);
  btn.title = previewKind(info.name) ? label : 'Ouvrir avec une autre application';
  btn.querySelector('span').textContent = label;
}

function renderMyFileCard(fileId) {
  const fd = myFiles.get(fileId);
  const card = document.createElement('div');
  card.className = 'file-card';
  card.id = 'fc-' + fileId;
  card.innerHTML = fileCardHtml(fileId, fd.name, fd.size, 'Vous', 'Disponible',
    `${previewButtonHtml(fileId)}
     <button class="btn-remove" title="Retirer ce fichier" aria-label="Retirer">${ICON_REMOVE}</button>`);
  card.querySelector('.btn-remove').addEventListener('click', () => removeMyFile(fileId));
  card.querySelector('.btn-preview')?.addEventListener('click', () => openFile(fileId));
  filesList.appendChild(card);
  updatePreviewButton(fileId);
}

function renderRemoteFileCard(info) {
  if (document.getElementById('fc-' + info.fileId)) return;
  const card = document.createElement('div');
  card.className = 'file-card';
  card.id = 'fc-' + info.fileId;
  card.innerHTML = fileCardHtml(info.fileId, info.name, info.size, info.senderPseudo, 'Prêt',
    `${previewButtonHtml(info.fileId)}
     <button class="btn-download" id="dl-${info.fileId}">${ICON_DOWNLOAD} Télécharger</button>`);
  card.querySelector('.btn-download').addEventListener('click', () => downloadRemote(info.fileId));
  card.querySelector('.btn-preview')?.addEventListener('click', () => openFile(info.fileId));
  filesList.appendChild(card);
  updatePreviewButton(info.fileId);
}

function downloadRemote(fileId) {
  // Already fetched for a preview: save that copy instead of transferring again
  const cached = localCopies.get(fileId);
  const info = remoteFiles.get(fileId);
  if (cached instanceof Blob && info) {
    saveBlob(cached, baseName(info.name));
    setDownloadUI(fileId, 'done', 'Téléchargé ✓');
    return;
  }
  startDownload(fileId).catch(err => showToast(err.message));
}

function removeFileCard(fileId) {
  document.getElementById('fc-' + fileId)?.remove();
}

function setDownloadUI(fileId, state, statusText) {
  const btn = document.getElementById('dl-' + fileId);
  const status = document.getElementById('status-' + fileId);
  const wrap = document.getElementById('prog-wrap-' + fileId);
  if (status) {
    status.textContent = statusText;
    status.classList.toggle('status-error', state === 'error');
  }
  if (btn) {
    btn.disabled = state === 'active';
    btn.innerHTML = state === 'active' ? 'En cours…' : `${ICON_DOWNLOAD} ${state === 'error' ? 'Réessayer' : 'Télécharger'}`;
  }
  if (wrap) {
    if (state === 'active') {
      wrap.style.display = '';
      updateDownloadProgress(fileId, 0, remoteFiles.get(fileId)?.size || 0);
    } else {
      setTimeout(() => { if (!activeDownloadFor(fileId)) wrap.style.display = 'none'; }, 800);
    }
  }
}

function updateDownloadProgress(fileId, received, total) {
  const pct = total ? Math.round((received / total) * 100) : 100;
  const bar = document.getElementById('prog-' + fileId);
  const label = document.getElementById('prog-label-' + fileId);
  if (bar) bar.style.width = pct + '%';
  if (label) label.textContent = `${formatSize(received)} / ${formatSize(total)} — ${pct}%`;
}

function renderUploadStatus(fileId) {
  const active = [...uploads.values()].filter(u => u.fileId === fileId);
  const wrap = document.getElementById('prog-wrap-' + fileId);
  const bar = document.getElementById('prog-' + fileId);
  const label = document.getElementById('prog-label-' + fileId);
  const status = document.getElementById('status-' + fileId);
  if (!wrap) return;
  if (!active.length) {
    wrap.style.display = 'none';
    if (status) status.textContent = 'Disponible';
    return;
  }
  const pct = Math.round(active.reduce((s, u) => s + u.pct, 0) / active.length);
  wrap.style.display = '';
  bar.style.width = pct + '%';
  label.textContent = active.length === 1
    ? `Envoi à ${active[0].pseudo}${active[0].via === 'relay' ? ' (relais)' : ''} — ${pct}%`
    : `${active.length} envois en cours — ${pct}%`;
  if (status) status.textContent = 'Envoi…';
}

function updateFilesUI() {
  const total = myFiles.size + remoteFiles.size;
  dropZone.classList.toggle('visible', total === 0);
  emptyState.classList.toggle('hidden', total > 0);
  filesList.classList.toggle('hidden', total === 0);
  btnZip.disabled = total === 0 || zipping;
  filesCount.textContent = total === 0 ? '0 fichier' : total === 1 ? '1 fichier' : `${total} fichiers`;
}

// ── FILE VIEWER ───────────────────────────────────────────────────
let viewerFileId = null;
let viewerName = '';
let viewerBlob = null;        // re-typed copy shown in the viewer
let viewerUrl = null;
let viewerReturnFocus = null;
const tabUrls = new Set();    // object URLs opened in other tabs, revoked when leaving the salon

async function getLocalCopy(fileId) {
  const own = myFiles.get(fileId);
  if (own) return own.file;
  const copy = localCopies.get(fileId);
  if (!copy) return null;
  if (copy instanceof Blob) return copy;
  try {
    return await copy.getFile();   // saved to disk via the File System Access API
  } catch {
    localCopies.delete(fileId);    // moved or deleted since
    updatePreviewButton(fileId);
    return null;
  }
}

async function openFile(fileId) {
  const info = myFiles.get(fileId) || remoteFiles.get(fileId);
  if (!info) return;
  const preview = previewKind(info.name);
  if (!preview) {
    openWithApp(fileId);
    return;
  }

  let source = await getLocalCopy(fileId);
  if (!source) {
    if (info.size > PREVIEW_MAX_BYTES) {
      showToast(window.showSaveFilePicker
        ? 'Fichier trop volumineux pour un aperçu direct : téléchargez-le, puis cliquez sur « Ouvrir ».'
        : 'Fichier trop volumineux pour un aperçu dans ce navigateur : ouvrez-le depuis vos téléchargements.', 6000);
      return;
    }
    const btn = document.getElementById('pv-' + fileId);
    if (btn) btn.disabled = true;
    try {
      source = await startDownload(fileId, { toMemory: true, doneText: 'Chargé ✓' });
    } catch (err) {
      showToast(err.message);
      return;
    } finally {
      if (btn) btn.disabled = false;
    }
    // The file may have been removed, or the salon left, while it was loading
    if (!source || !(myFiles.has(fileId) || remoteFiles.has(fileId))) return;
  }
  showViewer(fileId, info.name, preview, source, !myFiles.has(fileId));
}

// Hands the file to the OS share sheet, which lists the apps able to open it
async function shareFile(source, name) {
  const file = new File([source], baseName(name), { type: shareType(name) });
  try {
    await navigator.share({ files: [file], title: file.name });
  } catch (err) {
    if (err.name !== 'AbortError') showToast('Ouverture impossible ici : ouvrez le fichier depuis vos téléchargements.', 5000);
  }
}

async function openWithApp(fileId) {
  const info = myFiles.get(fileId) || remoteFiles.get(fileId);
  const source = info && await getLocalCopy(fileId);
  if (!source) {
    showToast('Téléchargez d\'abord le fichier.');
    return;
  }
  await shareFile(source, info.name);
}

function showViewer(fileId, name, { kind, type }, source, canSave) {
  closeViewer();
  viewerFileId = fileId;
  // Re-wrap with the type derived from the extension (never the sender's MIME type)
  viewerBlob = new Blob([source], { type });
  viewerUrl = URL.createObjectURL(viewerBlob);
  viewerTitle.textContent = baseName(name);
  viewerTitle.title = name;

  let el;
  if (kind === 'image') {
    el = document.createElement('img');
    el.alt = baseName(name);
    el.addEventListener('error', () => showViewerError('Image illisible ou format non pris en charge.'));
  } else if (kind === 'video' || kind === 'audio') {
    el = document.createElement(kind);
    el.controls = true;
    el.autoplay = true;
    el.addEventListener('error', () => showViewerError(`Format ${kind === 'video' ? 'vidéo' : 'audio'} non pris en charge par ce navigateur.`));
  } else if (kind === 'pdf') {
    el = document.createElement('iframe');
    el.title = baseName(name);
  } else {
    el = document.createElement('pre');
    el.textContent = 'Chargement…';
    const truncated = viewerBlob.size > TEXT_PREVIEW_MAX;
    viewerBlob.slice(0, TEXT_PREVIEW_MAX).text().then(text => {
      if (el.isConnected) el.textContent = text + (truncated ? '\n\n… (aperçu limité au premier Mo)' : '');
    });
  }
  if (kind !== 'text') el.src = viewerUrl;
  el.className = 'viewer-' + kind;
  viewerBody.replaceChildren(el);

  // An SVG opened as a top-level document could run scripts: only show it through <img>
  viewerTab.hidden = type === 'image/svg+xml';
  viewerSave.hidden = !canSave;
  viewerShare.hidden = !canOpenWith(name);
  viewerName = name;
  viewerReturnFocus = document.activeElement;
  viewer.hidden = false;
  viewerClose.focus();
}

function showViewerError(message) {
  const div = document.createElement('div');
  div.className = 'viewer-error';
  div.textContent = message;
  viewerBody.replaceChildren(div);
}

function closeViewer() {
  if (viewer.hidden) return;
  viewer.hidden = true;
  viewerBody.replaceChildren();   // stops any playing media
  if (viewerUrl) URL.revokeObjectURL(viewerUrl);
  viewerUrl = null;
  viewerBlob = null;
  viewerFileId = null;
  viewerReturnFocus?.focus?.();
  viewerReturnFocus = null;
}

viewerClose.addEventListener('click', closeViewer);
document.getElementById('viewer-backdrop').addEventListener('click', closeViewer);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !viewer.hidden) closeViewer();
});
viewerTab.addEventListener('click', () => {
  if (!viewerBlob) return;
  const url = URL.createObjectURL(viewerBlob);
  tabUrls.add(url);
  window.open(url, '_blank', 'noopener');
});
viewerShare.addEventListener('click', () => {
  if (viewerBlob) shareFile(viewerBlob, viewerName);
});
viewerSave.addEventListener('click', () => {
  const info = remoteFiles.get(viewerFileId);
  if (!viewerBlob || !info) return;
  saveBlob(viewerBlob, baseName(info.name));
  setDownloadUI(viewerFileId, 'done', 'Téléchargé ✓');
});

// ── QR SCANNER ────────────────────────────────────────────────────
let scanStream = null;
let scanTimer = null;
let jsQRLoading = null;

function loadJsQR() {
  if (window.jsQR) return Promise.resolve();
  jsQRLoading ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = '/vendor/jsQR.js';
    script.onload = resolve;
    script.onerror = () => { jsQRLoading = null; reject(new Error('lecteur QR indisponible')); };
    document.head.appendChild(script);
  });
  return jsQRLoading;
}

// Native BarcodeDetector when available (Chrome Android…), jsQR otherwise (iOS, Firefox)
async function makeQrDecoder() {
  if ('BarcodeDetector' in window) {
    try {
      if ((await BarcodeDetector.getSupportedFormats()).includes('qr_code')) {
        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        return async (video) => (await detector.detect(video))[0]?.rawValue || null;
      }
    } catch { /* fall back to jsQR */ }
  }
  await loadJsQR();
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  return async (video) => {
    const scale = Math.min(1, 640 / Math.max(video.videoWidth, video.videoHeight));
    canvas.width = Math.round(video.videoWidth * scale);
    canvas.height = Math.round(video.videoHeight * scale);
    if (!canvas.width || !canvas.height) return null;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' })?.data || null;
  };
}

async function openScanner() {
  if (!navigator.mediaDevices?.getUserMedia) {
    showToast('Caméra indisponible : l\'application doit être ouverte en HTTPS.', 5000);
    return;
  }
  scannerHint.textContent = 'Placez le QR code dans le cadre';
  scanner.hidden = false;
  try {
    const decode = await makeQrDecoder();
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
    if (scanner.hidden) { stream.getTracks().forEach(t => t.stop()); return; }  // closed while asking
    scanStream = stream;
    scannerVideo.srcObject = stream;
    await scannerVideo.play();

    const tick = async () => {
      if (scanner.hidden) return;
      let text = null;
      try { if (scannerVideo.readyState >= 2) text = await decode(scannerVideo); } catch { /* frame not ready */ }
      if (scanner.hidden || (text && handleScanned(text))) return;
      scanTimer = setTimeout(tick, 200);
    };
    tick();
  } catch (err) {
    closeScanner();
    const messages = { NotAllowedError: 'Accès à la caméra refusé.', NotFoundError: 'Aucune caméra trouvée.' };
    showToast(messages[err.name] || 'Caméra indisponible : ' + err.message, 5000);
  }
}

// Returns true when the code is an invite (scanning stops)
function handleScanned(text) {
  const invite = parseInvite(text);
  if (!invite) {
    scannerHint.textContent = 'Ce QR code n\'est pas une invitation P2P Share.';
    return false;
  }
  closeScanner();
  let url = null;
  try { url = new URL(text); } catch { /* bare "salonId-key" code */ }
  if (url && url.origin !== location.origin) {
    // Invite from another P2P Share server: only follow plain web links, after asking
    if (['https:', 'http:'].includes(url.protocol) && confirm(`Ce QR code mène vers un autre serveur :\n${url.origin}\n\nL'ouvrir ?`)) {
      location.href = url.href;
    }
    return true;
  }
  joinSalon(invite);
  return true;
}

function closeScanner() {
  clearTimeout(scanTimer);
  scanner.hidden = true;
  scannerVideo.srcObject = null;
  scanStream?.getTracks().forEach(t => t.stop());
  scanStream = null;
}

btnScan.addEventListener('click', openScanner);
document.getElementById('scanner-close').addEventListener('click', closeScanner);
document.getElementById('scanner-backdrop').addEventListener('click', closeScanner);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !scanner.hidden) closeScanner();
});

// ── PWA INSTALL ───────────────────────────────────────────────────
let installPrompt = null;

const isStandalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const isIos = () => /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

function updateInstallButton() {
  // Chrome/Edge/Android fire beforeinstallprompt; iOS needs manual "Add to Home Screen"
  btnInstall.hidden = isStandalone() || !(installPrompt || isIos());
}

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  installPrompt = e;
  updateInstallButton();
});
window.addEventListener('appinstalled', () => {
  installPrompt = null;
  updateInstallButton();
  showToast('Application installée.');
});
btnInstall.addEventListener('click', async () => {
  if (installPrompt) {
    installPrompt.prompt();
    await installPrompt.userChoice;
    installPrompt = null;
    updateInstallButton();
  } else if (isIos()) {
    showToast('Sur iPhone / iPad : touchez le bouton Partager, puis « Sur l\'écran d\'accueil ».', 8000);
  }
});

// ── DOWNLOAD ALL AS ZIP ───────────────────────────────────────────
function uniquePath(p, used) {
  let candidate = p;
  for (let n = 2; used.has(candidate.toLowerCase()); n++) {
    const dot = p.lastIndexOf('.');
    const slash = p.lastIndexOf('/');
    candidate = dot > slash + 1 ? `${p.slice(0, dot)} (${n})${p.slice(dot)}` : `${p} (${n})`;
  }
  used.add(candidate.toLowerCase());
  return candidate;
}

async function downloadAllZip() {
  if (zipping) return;
  const zipSalon = salonId;
  zipping = true;
  btnZip.disabled = true;
  const setLabel = (text) => { btnZip.textContent = text; };
  try {
    const zip = new JSZip();
    const used = new Set();
    for (const fd of myFiles.values()) zip.file(uniquePath(fd.name, used), fd.file);

    const remotes = [...remoteFiles.values()];
    let failed = 0;
    for (let i = 0; i < remotes.length; i++) {
      if (salonId !== zipSalon) return;
      setLabel(`Récupération ${i + 1}/${remotes.length}…`);
      try {
        const blob = await getLocalCopy(remotes[i].fileId)
          || await startDownload(remotes[i].fileId, { toMemory: true });
        zip.file(uniquePath(remotes[i].name, used), blob);
      } catch {
        failed++;
      }
    }
    if (salonId !== zipSalon || !Object.keys(zip.files).length) return;

    setLabel('Compression…');
    const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 1 } });
    saveBlob(blob, `salon-${zipSalon}.zip`);
    showToast(failed ? `Archive générée (${failed} fichier(s) n'ont pas pu être récupérés).` : 'Archive ZIP générée.', 5000);
  } catch (err) {
    showToast('Erreur ZIP : ' + err.message, 5000);
  } finally {
    zipping = false;
    btnZip.innerHTML = zipButtonHtml;
    updateFilesUI();
  }
}

// ── ACTION BINDINGS ───────────────────────────────────────────────
btnCreate.addEventListener('click', createSalon);

function onJoinClick() {
  const invite = parseInvite(joinCodeInput.value);
  if (!invite) { showToast('Collez le lien d\'invitation complet (ou le code salon-clé).'); return; }
  joinSalon(invite);
}
btnJoin.addEventListener('click', onJoinClick);
joinCodeInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') onJoinClick(); });

function confirmLeave() {
  if (confirm(isHost ? 'Quitter détruira le salon pour tous les membres. Continuer ?' : 'Quitter le salon ?')) {
    leaveSalon();
  }
}
btnLeave.addEventListener('click', confirmLeave);
document.getElementById('btn-leave-mobile').addEventListener('click', confirmLeave);

// Mobile top bar: "Inviter" / "Membres" open a drop-down panel
function setMobilePanel(panel) {
  if (panel) sidebar.dataset.panel = panel;
  else delete sidebar.dataset.panel;
  for (const btn of document.querySelectorAll('.mobile-action[data-panel]')) {
    btn.setAttribute('aria-expanded', String(btn.dataset.panel === panel));
  }
}
for (const btn of document.querySelectorAll('.mobile-action[data-panel]')) {
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    setMobilePanel(sidebar.dataset.panel === btn.dataset.panel ? null : btn.dataset.panel);
  });
}
document.addEventListener('click', (e) => {
  if (sidebar.dataset.panel && !e.target.closest('.sidebar-section')) setMobilePanel(null);
});

btnHome.addEventListener('click', () => showScreen('screen-home'));

btnCopy.addEventListener('click', () => {
  navigator.clipboard.writeText(inviteUrl()).then(() => {
    btnCopy.classList.add('copied');
    showToast('Lien copié ! Il contient la clé de chiffrement : partagez-le uniquement avec vos invités.', 4000);
    setTimeout(() => btnCopy.classList.remove('copied'), 2000);
  }, () => showToast('Copie impossible, sélectionnez le lien manuellement.'));
});

btnZip.addEventListener('click', downloadAllZip);

btnAddFiles.addEventListener('click', () => fileInput.click());
btnAddFolder.addEventListener('click', () => folderInput.click());

fileInput.addEventListener('change', () => {
  addFiles([...fileInput.files].map(file => ({ file, path: file.name })));
  fileInput.value = '';
});
folderInput.addEventListener('change', () => {
  addFiles([...folderInput.files].map(file => ({ file, path: file.webkitRelativePath || file.name })));
  folderInput.value = '';
});

// Drag & drop
function inSalonScreen() {
  return currentScreen === 'screen-salon';
}
document.addEventListener('dragover', (e) => {
  if (!inSalonScreen()) return;
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
document.addEventListener('dragleave', (e) => {
  if (!e.relatedTarget) dropZone.classList.remove('drag-over');
});
document.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (!inSalonScreen()) return;
  collectDropped(e.dataTransfer)
    .then(entries => { if (entries.length) addFiles(entries); })
    .catch(err => showToast('Lecture impossible : ' + err.message));
});

// ── INIT ──────────────────────────────────────────────────────────
function init() {
  initPseudo();
  initSocket();

  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('/sw.js').catch(err => console.warn('SW registration failed:', err));
  }
  btnScan.hidden = !navigator.mediaDevices?.getUserMedia;
  updateInstallButton();

  const invite = parseInvite(location.href);
  const session = getSession();
  if (invite && session && session.salonId === invite.salonId && session.key === invite.key) {
    // Reload (or tab killed by the phone): take our place back instead of joining as someone new
    resumeSession(session);
  } else if (invite) {
    // Opened from an invite link or QR code: join right away with the current pseudo
    joinSalon(invite, { fromLink: true });
  }
}

init();
