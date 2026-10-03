const http = require('node:http');
const fs = require('node:fs');
const { randomBytes, randomUUID } = require('node:crypto');
const { WebSocketServer, WebSocket } = require('ws');

const port = Number(process.env.PORT || 3000);
const root = __dirname;
const publicFiles = new Set(['/index.html', '/app.js', '/styles.css', '/space-logo.svg', '/space-logo.png']);
const rooms = new Map();
const waitingUsers = new Set();
const matchRequests = new Map();
const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

const server = http.createServer((request, response) => {
  const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
  const requestedPath = pathname === '/' ? '/index.html' : pathname;
  if (!publicFiles.has(requestedPath)) {
    response.writeHead(404).end('Not found');
    return;
  }
  const filePath = `${root}${requestedPath}`;

  fs.readFile(filePath, (error, content) => {
    if (error) {
      response.writeHead(404).end('Not found');
      return;
    }
    response.writeHead(200, {
      'Content-Type': contentTypes[requestedPath.slice(requestedPath.lastIndexOf('.'))] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    }).end(content);
  });
});

const sockets = new WebSocketServer({ server, maxPayload: 16_384 });

function removeFromRoom(socket, announce = true) {
  if (!socket.room) return;
  const room = rooms.get(socket.room);
  if (room) {
    room.peers.delete(socket);
    if (announce) {
      for (const peer of room.peers) send(peer, { type: 'peer-left' });
    }
    if (room.peers.size === 0) {
      clearTimeout(room.timer);
      rooms.delete(socket.room);
    }
  }
  socket.room = null;
}

function send(socket, message) {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
}

function broadcastAvailable() {
  for (const client of sockets.clients) {
    const count = Array.from(waitingUsers).filter((candidate) => candidate !== client && candidate.readyState === WebSocket.OPEN).length;
    send(client, { type: 'match-count', count });
  }
}

function createRoom(roomId, duration) {
  const minutes = [5, 15, 30, 60].includes(duration) ? duration : 15;
  const room = { peers: new Set(), expiresAt: Date.now() + minutes * 60_000 };
  room.timer = setTimeout(() => {
    for (const peer of room.peers) {
      send(peer, { type: 'session-ended' });
      peer.room = null;
      peer.close();
    }
    room.peers.clear();
    rooms.delete(roomId);
  }, minutes * 60_000);
  rooms.set(roomId, room);
  return room;
}

function finishMatchRequest(request, accepted, expired = false) {
  clearTimeout(request.timer);
  matchRequests.delete(request.id);
  request.requester.matchRequestId = null;
  request.target.matchRequestId = null;

  if (accepted && request.requester.readyState === WebSocket.OPEN && request.target.readyState === WebSocket.OPEN) {
    const roomId = randomBytes(16).toString('hex');
    const room = createRoom(roomId, request.duration);
    for (const [peer, initiator] of [[request.requester, true], [request.target, false]]) {
      peer.matchState = null;
      peer.room = roomId;
      room.peers.add(peer);
      send(peer, {
        type: 'match-ready',
        room: roomId,
        initiator,
        expiresAt: room.expiresAt,
        duration: request.duration,
      });
    }
  } else {
    request.target.matchState = null;
    if (request.requester.readyState === WebSocket.OPEN) {
      request.requester.matchState = 'waiting';
      waitingUsers.add(request.requester);
      send(request.requester, { type: expired ? 'request-expired' : 'request-declined' });
    }
    if (request.target.readyState === WebSocket.OPEN) {
      send(request.target, { type: expired ? 'request-expired' : 'request-dismissed' });
    }
  }
  broadcastAvailable();
}

function removeFromMatchmaking(socket) {
  if (socket.matchState === 'waiting') waitingUsers.delete(socket);

  if (socket.matchRequestId) {
    const request = matchRequests.get(socket.matchRequestId);
    if (request) {
      clearTimeout(request.timer);
      matchRequests.delete(request.id);
      const other = request.requester === socket ? request.target : request.requester;
      other.matchRequestId = null;
      if (other.readyState === WebSocket.OPEN) {
        other.matchState = 'waiting';
        waitingUsers.add(other);
        send(other, { type: request.requester === socket ? 'request-canceled' : 'request-expired' });
      }
    }
  }

  socket.matchRequestId = null;
  socket.matchState = null;
  broadcastAvailable();
}

function requestRandomMatch(socket, duration) {
  if (socket.room || socket.matchState) return;
  const candidates = Array.from(waitingUsers).filter((candidate) => candidate !== socket
    && candidate.readyState === WebSocket.OPEN
    && candidate.matchState === 'waiting'
    && !candidate.room);
  const target = candidates.length ? candidates[Math.floor(Math.random() * candidates.length)] : null;

  if (!target) {
    socket.matchState = 'waiting';
    waitingUsers.add(socket);
    send(socket, { type: 'match-waiting' });
    broadcastAvailable();
    return;
  }

  waitingUsers.delete(target);
  const request = {
    id: randomUUID(),
    requester: socket,
    target,
    duration: [5, 15, 30, 60].includes(duration) ? duration : 15,
  };
  request.timer = setTimeout(() => finishMatchRequest(request, false, true), 30_000);
  matchRequests.set(request.id, request);
  socket.matchState = 'requesting';
  target.matchState = 'requested';
  socket.matchRequestId = request.id;
  target.matchRequestId = request.id;
  send(socket, { type: 'request-sent' });
  send(target, {
    type: 'match-request',
    requestId: request.id,
    duration: request.duration,
  });
  broadcastAvailable();
}

sockets.on('connection', (socket) => {
  socket.on('message', (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (message.type === 'match-start') {
      requestRandomMatch(socket, message.duration);
      return;
    }
    if (message.type === 'match-cancel') {
      removeFromMatchmaking(socket);
      send(socket, { type: 'match-canceled' });
      return;
    }
    if (message.type === 'match-respond') {
      const request = matchRequests.get(message.requestId);
      if (request?.target === socket) finishMatchRequest(request, message.accept === true);
      return;
    }

    if (message.type === 'join' && typeof message.room === 'string' && /^[a-f0-9]{32}$/.test(message.room)) {
      removeFromRoom(socket);
      let room = rooms.get(message.room);
      if (!room) room = createRoom(message.room, message.duration);
      if (room.peers.size >= 2) {
        send(socket, { type: 'room-full' });
        return;
      }
      room.peers.add(socket);
      socket.room = message.room;
      send(socket, { type: 'joined', initiator: room.peers.size === 1, expiresAt: room.expiresAt });
      if (room.peers.size === 2) {
        for (const peer of room.peers) if (peer !== socket) send(peer, { type: 'peer-joined' });
      }
      return;
    }

    if (!socket.room) return;
    const room = rooms.get(socket.room);
    if (!room) return;
    if (message.type === 'end') {
      clearTimeout(room.timer);
      for (const peer of room.peers) {
        send(peer, { type: 'session-ended' });
        peer.room = null;
        peer.close();
      }
      room.peers.clear();
      rooms.delete(socket.room);
      return;
    }
    if (message.type === 'signal' && typeof message.description === 'object') {
      for (const peer of room.peers) if (peer !== socket) send(peer, { type: 'signal', description: message.description });
    }
    if (message.type === 'match-key' && typeof message.publicKey === 'string' && message.publicKey.length <= 200) {
      for (const peer of room.peers) if (peer !== socket) send(peer, { type: 'match-key', publicKey: message.publicKey });
    }
  });

  send(socket, { type: 'match-count', count: waitingUsers.size });
  socket.on('close', () => {
    removeFromMatchmaking(socket);
    removeFromRoom(socket);
  });
  socket.on('error', () => {
    removeFromMatchmaking(socket);
    removeFromRoom(socket);
  });
});

server.listen(port, '0.0.0.0', () => {
  console.log(`SPACE is listening on http://localhost:${port}`);
});