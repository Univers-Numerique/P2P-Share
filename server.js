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
const HOST_GRACE_MS = 30_000;                 // time an absent host has to come back
const MAX_CHUNK_BYTES = 80 * 1024;            // 64 KiB payload + tag/IV/GCM overhead
const MAX_META_BYTES = 4 * 1024;
const MAX_CTRL_BYTES = 1024;
const RELAY_BYTES_PER_MIN = Number(process.env.RELAY_BYTES_PER_MIN) || 300 * 1024 * 1024;
const MAX_SALONS = 10_000;

const ID_RE     = /^[0-9a-f]{16}$/;           // fileId / transferId
const SALON_RE  = /^[0-9a-f]{8}$/;
const HEX64_RE  = /^[0-9a-f]{64}$/;           // auth token
const TOKEN_RE  = /^[0-9a-f]{32}$/;           // host token
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
// salonId -> { id, hostId, hostToken, authHash, members: Map<socketId, {pseudo, peerId}>, hostTimer }
const salons = new Map();

const sha256 = (s) => crypto.createHash('sha256').update(s).digest();
const safeEqual = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

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
  for (const [sid, info] of salon.members) {
    if (sid !== exceptId) list.push({ socketId: sid, pseudo: info.pseudo, peerId: info.peerId, isHost: sid === salon.hostId });
  }
  return list;
}

// Returns the target socket only if it belongs to the sender's salon
function memberSocket(socket, to) {
  const salon = salonOf(socket);
  if (!salon || typeof to !== 'string' || to === socket.id || !salon.members.has(to)) return null;
  return io.sockets.sockets.get(to) || null;
}

function addToSalon(socket, salon, pseudo) {
  salon.members.set(socket.id, { pseudo, peerId: null });
  socket.join(salon.id);
  socket.data.salonId = salon.id;
  socket.data.pseudo = pseudo;
}

function destroySalon(salon, reason) {
  clearTimeout(salon.hostTimer);
  io.to(salon.id).emit('salon-destroyed', { reason });
  for (const sid of salon.members.keys()) {
    const s = io.sockets.sockets.get(sid);
    if (s) { s.leave(salon.id); s.data.salonId = null; }
  }
  salons.delete(salon.id);
}

function leaveSalon(socket, explicit) {
  const salon = salonOf(socket);
  if (!salon) return;
  salon.members.delete(socket.id);
  socket.leave(salon.id);
  socket.data.salonId = null;

  if (salon.hostId === socket.id) {
    if (explicit) { destroySalon(salon, 'L\'hôte a fermé le salon.'); return; }
    // Host dropped (refresh, network): give them a chance to come back
    salon.hostId = null;
    io.to(salon.id).emit('member-left', { socketId: socket.id, pseudo: socket.data.pseudo });
    io.to(salon.id).emit('host-away', { graceMs: HOST_GRACE_MS });
    salon.hostTimer = setTimeout(() => destroySalon(salon, 'L\'hôte a quitté le salon.'), HOST_GRACE_MS);
    return;
  }
  io.to(salon.id).emit('member-left', { socketId: socket.id, pseudo: socket.data.pseudo });
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

    leaveSalon(socket, true);
    let id;
    do { id = crypto.randomBytes(4).toString('hex'); } while (salons.has(id));
    const hostToken = crypto.randomBytes(16).toString('hex');
    const salon = { id, hostId: socket.id, hostToken, authHash: sha256(p.auth), members: new Map(), hostTimer: null };
    salons.set(id, salon);
    addToSalon(socket, salon, pseudo);
    ack({ ok: true, salonId: id, hostToken, members: [] });
  });

  on('join-salon', (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!joinLimiter(ip)) return ack({ ok: false, error: 'Trop de tentatives, réessayez dans une minute.' });
    const pseudo = cleanPseudo(p?.pseudo);
    const salon = SALON_RE.test(p?.salonId) ? salons.get(p.salonId) : null;
    if (!pseudo || !salon || !HEX64_RE.test(p?.auth) || !safeEqual(sha256(p.auth), salon.authHash)) {
      return ack({ ok: false, error: 'Salon introuvable ou lien invalide.' });
    }
    if (salon.id !== socket.data.salonId) leaveSalon(socket, true);
    addToSalon(socket, salon, pseudo);
    ack({ ok: true, salonId: salon.id, members: memberList(salon, socket.id), hostAway: !salon.hostId });
    socket.to(salon.id).emit('member-joined', { socketId: socket.id, pseudo, isHost: false });
  });

  on('resume-host', (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!joinLimiter(ip)) return ack({ ok: false, error: 'Trop de tentatives, réessayez dans une minute.' });
    const pseudo = cleanPseudo(p?.pseudo);
    const salon = SALON_RE.test(p?.salonId) ? salons.get(p.salonId) : null;
    if (!pseudo || !salon || salon.hostId || !TOKEN_RE.test(p?.hostToken) ||
        !safeEqual(Buffer.from(p.hostToken), Buffer.from(salon.hostToken))) {
      return ack({ ok: false, error: 'Le salon a expiré.' });
    }
    clearTimeout(salon.hostTimer);
    salon.hostTimer = null;
    salon.hostId = socket.id;
    addToSalon(socket, salon, pseudo);
    ack({ ok: true, salonId: salon.id, members: memberList(salon, socket.id) });
    socket.to(salon.id).emit('member-joined', { socketId: socket.id, pseudo, isHost: true });
  });

  on('leave-salon', () => leaveSalon(socket, true));

  on('register-peer', (p) => {
    const salon = salonOf(socket);
    if (!salon || !PEER_RE.test(p?.peerId)) return;
    salon.members.get(socket.id).peerId = p.peerId;
    socket.to(salon.id).emit('peer-registered', { socketId: socket.id, peerId: p.peerId });
  });

  // File metadata is encrypted client-side: the server only forwards opaque bytes
  on('file-announce', (p) => {
    const salon = salonOf(socket);
    if (!salon || !ID_RE.test(p?.fileId) || !Buffer.isBuffer(p.meta) || p.meta.length > MAX_META_BYTES) return;
    const payload = { from: socket.id, fileId: p.fileId, meta: p.meta };
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
    socket.to(salon.id).emit('file-remove', { from: socket.id, fileId: p.fileId });
  });

  // ── RELAY (fallback when WebRTC cannot connect) ──
  on('relay-ctrl', (p) => {
    const target = memberSocket(socket, p?.to);
    if (!target || !p.msg || typeof p.msg !== 'object') return;
    if (JSON.stringify(p.msg).length > MAX_CTRL_BYTES) return;
    target.emit('relay-ctrl', { from: socket.id, msg: p.msg });
  });

  on('relay-chunk', (p, ack) => {
    if (typeof ack !== 'function') return;
    const target = memberSocket(socket, p?.to);
    if (!target || !Buffer.isBuffer(p.data) || p.data.length > MAX_CHUNK_BYTES) return ack({ ok: false });
    if (!relayLimiter(ip, p.data.length)) return ack({ ok: false, error: 'rate' });
    // Ack the sender only once the receiver has processed the chunk (end-to-end backpressure)
    target.timeout(30_000).emit('relay-chunk', { from: socket.id, data: p.data }, (err, res) => {
      ack({ ok: !err && res?.ok === true });
    });
  });

  on('disconnect', () => leaveSalon(socket, false));
});

server.listen(PORT, HOST, () => {
  const proto = server instanceof https.Server ? 'https' : 'http';
  console.log(`P2P Share running on ${proto}://localhost:${PORT} (bound to ${HOST})`);
});
