'use strict';

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');
const { ExpressPeerServer } = require('peer');
const { WebSocketServer } = require('ws');

// ── CONFIG ────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
// How long a disconnected member (phone locked, network switch…) keeps its place
const SESSION_GRACE_MS = Number(process.env.SESSION_GRACE_MS) || 15 * 60_000;
const MAX_CHUNK_BYTES = 80 * 1024;            // 64 KiB payload + tag/IV/GCM overhead
const MAX_META_BYTES = 4 * 1024;
const MAX_CTRL_BYTES = 1024;
const RELAY_BYTES_PER_MIN = Number(process.env.RELAY_BYTES_PER_MIN) || 300 * 1024 * 1024;
const MAX_SALONS = 10_000;

const ID_RE     = /^[0-9a-f]{16}$/;           // fileId / transferId / memberId
const SALON_RE  = /^[0-9a-f]{8}$/;
const HEX64_RE  = /^[0-9a-f]{64}$/;           // auth token
const TOKEN_RE  = /^[0-9a-f]{32}$/;           // member session token
const PEER_RE   = /^[A-Za-z0-9_-]{1,64}$/;

// ── HTTP ──────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');
if (TRUST_PROXY) app.set('trust proxy', 1);

const server = process.env.SSL_KEY && process.env.SSL_CERT
  ? https.createServer({ key: fs.readFileSync(process.env.SSL_KEY), cert: fs.readFileSync(process.env.SSL_CERT) }, app)
  : http.createServer(app);

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "frame-src 'self' blob:",
    "object-src 'none'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'none'"
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Self-hosted PeerJS signaling (no third-party broker).
// Its WebSocket server runs in noServer mode: attached directly to the HTTP server,
// `ws` would answer 400 to every other upgrade and break Socket.io.
let peerWss = null;
app.use('/peerjs', ExpressPeerServer(server, {
  path: '/',
  allow_discovery: false,
  proxied: TRUST_PROXY,
  createWebSocketServer: (options) => (peerWss = new WebSocketServer({ noServer: true, path: options.path }))
}));
server.on('upgrade', (req, socket, head) => {
  if (!peerWss || !req.url.startsWith(peerWss.options.path)) return; // Socket.io handles its own
  peerWss.handleUpgrade(req, socket, head, (ws) => peerWss.emit('connection', ws, req));
});

// Client libraries served from node_modules instead of a CDN
const vendor = {
  'peerjs.min.js': 'peerjs/dist/peerjs.min.js',
  'qrcode.min.js': 'qrcodejs/qrcode.min.js',
  'jszip.min.js':  'jszip/dist/jszip.min.js',
  'jsQR.js':       'jsqr/dist/jsQR.js'
};
for (const [name, file] of Object.entries(vendor)) {
  app.get('/vendor/' + name, (req, res) => res.sendFile(path.join(__dirname, 'node_modules', file)));
}

// ICE servers (optional TURN via env).
// With TURN_SECRET (coturn "use-auth-secret"), each visitor gets short-lived credentials
// so the shared secret never leaves the server.
const TURN_TTL_S = 12 * 3600;
app.get('/config', (req, res) => {
  const iceServers = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
  if (process.env.TURN_URLS) {
    const urls = process.env.TURN_URLS.split(',').map(s => s.trim());
    if (process.env.TURN_SECRET) {
      const username = `${Math.floor(Date.now() / 1000) + TURN_TTL_S}:p2pshare`;
      const credential = crypto.createHmac('sha1', process.env.TURN_SECRET).update(username).digest('base64');
      iceServers.push({ urls, username, credential });
    } else {
      iceServers.push({ urls, username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL });
    }
  }
  res.set('Cache-Control', 'no-store');
  res.json({ iceServers });
});

app.use(express.static(path.join(__dirname, 'public')));

// ── SOCKET.IO ─────────────────────────────────────────────────────
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

const io = new Server(server, {
  maxHttpBufferSize: 256 * 1024,
  allowRequest: (req, cb) => cb(null, originAllowed(req))
});

// ── RATE LIMITING ─────────────────────────────────────────────────
function makeLimiter(max, windowMs) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, e] of hits) if (now > e.reset) hits.delete(k);
  }, windowMs).unref();
  return (key, cost = 1) => {
    const now = Date.now();
    let e = hits.get(key);
    if (!e || now > e.reset) { e = { used: 0, reset: now + windowMs }; hits.set(key, e); }
    e.used += cost;
    return e.used <= max;
  };
}
const joinLimiter   = makeLimiter(20, 60_000);
const createLimiter = makeLimiter(10, 60_000);
const relayLimiter  = makeLimiter(RELAY_BYTES_PER_MIN, 60_000);

function clientIp(socket) {
  if (TRUST_PROXY) {
    const fwd = socket.handshake.headers['x-forwarded-for'];
    if (fwd) return String(fwd).split(',')[0].trim();
  }
  return socket.handshake.address;
}

// ── HELPERS ───────────────────────────────────────────────────────
// A member keeps a stable memberId across reconnections (phone locked, network switch,
// page reload). Its socket can come and go: while socketId is null the member is "away".
// salonId -> { id, hostId, authHash, members: Map<memberId, Member> }
// Member: { pseudo, peerId, token, socketId, awayTimer }
const salons = new Map();

const sha256 = (s) => crypto.createHash('sha256').update(s).digest();
const safeEqual = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

function cleanPseudo(p) {
  if (typeof p !== 'string') return null;
  const s = p.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 24);
  return s || null;
}

function salonOf(socket) {
  const id = socket.data.salonId;
  return id ? salons.get(id) || null : null;
}

function memberList(salon, exceptId) {
  const list = [];
  for (const [id, m] of salon.members) {
    if (id !== exceptId) {
      list.push({ memberId: id, pseudo: m.pseudo, peerId: m.peerId, isHost: id === salon.hostId, away: !m.socketId });
    }
  }
  return list;
}

// Returns the target's current socket only if it belongs to the sender's salon and is online
function memberSocket(socket, to) {
  const salon = salonOf(socket);
  if (!salon || typeof to !== 'string' || to === socket.data.memberId) return null;
  const target = salon.members.get(to);
  return target?.socketId ? io.sockets.sockets.get(target.socketId) || null : null;
}

function attach(socket, salon, memberId) {
  const member = salon.members.get(memberId);
  clearTimeout(member.awayTimer);
  member.awayTimer = null;
  member.socketId = socket.id;
  socket.join(salon.id);
  socket.data.salonId = salon.id;
  socket.data.memberId = memberId;
}

function detach(socket) {
  const salon = salonOf(socket);
  if (salon) socket.leave(salon.id);
  socket.data.salonId = null;
  socket.data.memberId = null;
}

function addMember(socket, salon, pseudo) {
  const memberId = randomHex(8);
  const token = randomHex(16);
  salon.members.set(memberId, { pseudo, peerId: null, token, socketId: null, awayTimer: null });
  attach(socket, salon, memberId);
  return { memberId, token };
}

function destroySalon(salon, reason) {
  io.to(salon.id).emit('salon-destroyed', { reason });
  for (const m of salon.members.values()) {
    clearTimeout(m.awayTimer);
    const s = m.socketId && io.sockets.sockets.get(m.socketId);
    if (s) detach(s);
  }
  salons.delete(salon.id);
}

function removeMember(salon, memberId, reason) {
  const member = salon.members.get(memberId);
  if (!member) return;
  if (memberId === salon.hostId) { destroySalon(salon, reason); return; }
  clearTimeout(member.awayTimer);
  salon.members.delete(memberId);
  io.to(salon.id).emit('member-left', { memberId, pseudo: member.pseudo });
}

// Explicit "Quitter": immediate
function leaveSalon(socket) {
  const salon = salonOf(socket);
  const memberId = socket.data.memberId;
  if (!salon || !memberId) return;
  detach(socket);
  removeMember(salon, memberId, 'L\'hôte a fermé le salon.');
}

// Connection lost (phone locked, network switch, reload): the member stays, marked as away
function markAway(socket) {
  const salon = salonOf(socket);
  const memberId = socket.data.memberId;
  const member = salon?.members.get(memberId);
  if (!member || member.socketId !== socket.id) return;
  detach(socket);
  member.socketId = null;
  io.to(salon.id).emit('member-away', { memberId, graceMs: SESSION_GRACE_MS });
  member.awayTimer = setTimeout(() => {
    removeMember(salon, memberId, 'L\'hôte n\'est pas revenu à temps.');
  }, SESSION_GRACE_MS);
}

// ── EVENTS ────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  const ip = clientIp(socket);
  const on = (event, handler) => socket.on(event, (...args) => {
    try { handler(...args); } catch (err) { console.error(`[${event}]`, err); }
  });

  on('create-salon', (p, ack) => {
    if (typeof ack !== 'function') return;
    const pseudo = cleanPseudo(p?.pseudo);
    if (!pseudo || !HEX64_RE.test(p?.auth)) return ack({ ok: false, error: 'Requête invalide.' });
    if (!createLimiter(ip)) return ack({ ok: false, error: 'Trop de salons créés, réessayez dans une minute.' });
    if (salons.size >= MAX_SALONS) return ack({ ok: false, error: 'Serveur saturé, réessayez plus tard.' });

    leaveSalon(socket);
    let id;
    do { id = randomHex(4); } while (salons.has(id));
    const salon = { id, hostId: null, authHash: sha256(p.auth), members: new Map() };
    salons.set(id, salon);
    const { memberId, token } = addMember(socket, salon, pseudo);
    salon.hostId = memberId;
    ack({ ok: true, salonId: id, memberId, token, isHost: true, members: [] });
  });

  on('join-salon', (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!joinLimiter(ip)) return ack({ ok: false, error: 'Trop de tentatives, réessayez dans une minute.' });
    const pseudo = cleanPseudo(p?.pseudo);
    const salon = SALON_RE.test(p?.salonId) ? salons.get(p.salonId) : null;
    if (!pseudo || !salon || !HEX64_RE.test(p?.auth) || !safeEqual(sha256(p.auth), salon.authHash)) {
      return ack({ ok: false, error: 'Salon introuvable ou lien invalide.' });
    }
    leaveSalon(socket);
    const { memberId, token } = addMember(socket, salon, pseudo);
    const host = salon.members.get(salon.hostId);
    ack({ ok: true, salonId: salon.id, memberId, token, isHost: false, members: memberList(salon, memberId), hostAway: !host?.socketId });
    socket.to(salon.id).emit('member-joined', { memberId, pseudo, isHost: false });
  });

  // Takes back an existing identity after a disconnection (same memberId, same files)
  on('resume-session', (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!joinLimiter(ip)) return ack({ ok: false, error: 'Trop de tentatives, réessayez dans une minute.' });
    const salon = SALON_RE.test(p?.salonId) ? salons.get(p.salonId) : null;
    const member = salon && ID_RE.test(p?.memberId) ? salon.members.get(p.memberId) : null;
    if (!member || !TOKEN_RE.test(p?.token) || !safeEqual(Buffer.from(p.token), Buffer.from(member.token))) {
      return ack({ ok: false, error: 'Session expirée.' });
    }
    const memberId = p.memberId;
    if (socket.data.memberId !== memberId) leaveSalon(socket);

    // The old connection may not be detected as dead yet (typical after a phone sleep)
    const old = member.socketId && member.socketId !== socket.id ? io.sockets.sockets.get(member.socketId) : null;
    if (old) {
      detach(old);
      old.emit('session-replaced');
      old.disconnect(true);
    }
    const wasAway = !member.socketId || !!old;
    const pseudo = cleanPseudo(p?.pseudo);
    if (pseudo) member.pseudo = pseudo;
    attach(socket, salon, memberId);

    const isHost = memberId === salon.hostId;
    ack({ ok: true, salonId: salon.id, memberId, isHost, members: memberList(salon, memberId) });
    if (wasAway) socket.to(salon.id).emit('member-back', { memberId, pseudo: member.pseudo, isHost });
  });

  on('leave-salon', () => leaveSalon(socket));

  on('register-peer', (p) => {
    const salon = salonOf(socket);
    if (!salon || !PEER_RE.test(p?.peerId)) return;
    salon.members.get(socket.data.memberId).peerId = p.peerId;
    socket.to(salon.id).emit('peer-registered', { memberId: socket.data.memberId, peerId: p.peerId });
  });

  // File metadata is encrypted client-side: the server only forwards opaque bytes
  on('file-announce', (p) => {
    const salon = salonOf(socket);
    if (!salon || !ID_RE.test(p?.fileId) || !Buffer.isBuffer(p.meta) || p.meta.length > MAX_META_BYTES) return;
    const payload = { from: socket.data.memberId, fileId: p.fileId, meta: p.meta };
    if (p.to !== undefined) {
      const target = memberSocket(socket, p.to);
      if (target) target.emit('file-announce', payload);
    } else {
      socket.to(salon.id).emit('file-announce', payload);
    }
  });

  on('file-remove', (p) => {
    const salon = salonOf(socket);
    if (!salon || !ID_RE.test(p?.fileId)) return;
    socket.to(salon.id).emit('file-remove', { from: socket.data.memberId, fileId: p.fileId });
  });

  // After a reload the member's files are gone: others drop whatever is no longer listed
  on('file-sync', (p) => {
    const salon = salonOf(socket);
    const ids = Array.isArray(p?.fileIds) ? p.fileIds : null;
    if (!salon || !ids || ids.length > 5000 || !ids.every(id => ID_RE.test(id))) return;
    socket.to(salon.id).emit('file-sync', { from: socket.data.memberId, fileIds: ids });
  });

  // ── RELAY (fallback when WebRTC cannot connect) ──
  on('relay-ctrl', (p) => {
    const target = memberSocket(socket, p?.to);
    if (!target || !p.msg || typeof p.msg !== 'object') return;
    if (JSON.stringify(p.msg).length > MAX_CTRL_BYTES) return;
    target.emit('relay-ctrl', { from: socket.data.memberId, msg: p.msg });
  });

  on('relay-chunk', (p, ack) => {
    if (typeof ack !== 'function') return;
    const target = memberSocket(socket, p?.to);
    if (!target || !Buffer.isBuffer(p.data) || p.data.length > MAX_CHUNK_BYTES) return ack({ ok: false });
    if (!relayLimiter(ip, p.data.length)) return ack({ ok: false, error: 'rate' });
    // Ack the sender only once the receiver has processed the chunk (end-to-end backpressure)
    target.timeout(30_000).emit('relay-chunk', { from: socket.data.memberId, data: p.data }, (err, res) => {
      ack({ ok: !err && res?.ok === true });
    });
  });

  on('disconnect', () => markAway(socket));
});

server.listen(PORT, HOST, () => {
  const proto = server instanceof https.Server ? 'https' : 'http';
  console.log(`P2P Share running on ${proto}://localhost:${PORT} (bound to ${HOST})`);
});
