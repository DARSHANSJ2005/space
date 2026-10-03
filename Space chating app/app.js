const introView = document.querySelector('#intro-view');
const chatView = document.querySelector('#chat-view');
const nameInput = document.querySelector('#display-name');
const durationSelect = document.querySelector('#duration');
const randomDurationSelect = document.querySelector('#random-duration');
const inviteInput = document.querySelector('#invite-input');
const errorLabel = document.querySelector('#form-error');
const inviteAddress = document.querySelector('#invite-address');
const inviteStrip = document.querySelector('#invite-strip');
const connectionState = document.querySelector('#connection-state');
const connectionLabel = document.querySelector('#connection-label');
const roomTitle = document.querySelector('#room-title');
const countdown = document.querySelector('#countdown');
const messages = document.querySelector('#messages');
const messageInput = document.querySelector('#message-input');
const sendButton = document.querySelector('#send-button');
const notice = document.querySelector('#notice');
const privacyDialog = document.querySelector('#privacy-dialog');
const availableCount = document.querySelector('#available-count');
const randomStatus = document.querySelector('#random-status');
const findRandomButton = document.querySelector('#find-random-button');
const cancelRandomButton = document.querySelector('#cancel-random-button');
const matchDialog = document.querySelector('#match-dialog');
const matchRequestDetails = document.querySelector('#match-request-details');
const inviteLink = document.querySelector('#invite-link');

let socket;
let lobbySocket;
let peerConnection;
let dataChannel;
let encryptionKey;
let ecdhKeyPair;
let roomId;
let expiresAt;
let displayName = 'Guest';
let countdownTimer;
let noticeTimer;
let joinedAsHost = false;
let randomSession = false;
let chatReady = false;
let pageLeaving = false;
let beginMatchWhenConnected = false;
let queuedMatchDuration = 15;
let activeMatchRequestId;
let pendingPeerPublicKey;
const spaceCodeAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function encodeBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decodeBase64Url(value) {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeSpaceCode(bytes) {
  let buffer = 0;
  let bits = 0;
  let code = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      code += spaceCodeAlphabet[(buffer >>> bits) & 31];
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits > 0) code += spaceCodeAlphabet[(buffer << (5 - bits)) & 31];
  return code.match(/.{1,4}/g).join('-');
}

function decodeSpaceCode(value) {
  const code = value.toUpperCase().replaceAll('-', '').replaceAll(' ', '');
  if (!/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{26}$/.test(code)) {
    throw new Error('Enter the full 26-character SPACE code.');
  }
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const character of code) {
    buffer = (buffer << 5) | spaceCodeAlphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 255);
      buffer &= (1 << bits) - 1;
    }
  }
  if (bytes.length !== 16 || bits !== 2 || buffer !== 0) {
    throw new Error('That SPACE code is invalid. Ask for a new one.');
  }
  return Uint8Array.from(bytes);
}

async function getSpaceId(secretBytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', secretBytes));
  return Array.from(digest.slice(0, 16), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function getInviteUrl(code) {
  const url = new URL(window.location.href);
  url.searchParams.set('space', code);
  return url.toString();
}

function updateInviteUrl(code) {
  if (!code) return;
  const url = new URL(window.location.href);
  url.searchParams.set('space', code);
  window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
}

function clearInviteUrl() {
  const url = new URL(window.location.href);
  url.searchParams.delete('space');
  url.searchParams.delete('invite');
  url.searchParams.delete('code');
  window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
}

function normalizeInviteInput(value) {
  const source = (value || '').trim();
  if (!source) return '';

  try {
    const url = new URL(source);
    const key = url.searchParams.get('space') || url.searchParams.get('invite') || url.searchParams.get('code');
    if (key) return key.trim();
    const pathname = url.pathname.replace(/^\/+|\/+$/g, '');
    if (pathname) return pathname.trim();
  } catch {
    // Not a URL, continue with raw text parsing.
  }

  return source.replace(/^https?:\/\/[^\s]+\?[^\s]*?(space|invite|code)\s*=\s*/i, '').trim();
}

async function parseInvite(value) {
  const candidate = normalizeInviteInput(value);
  const normalized = candidate.trim();

  if (!normalized) {
    throw new Error('Paste a valid SPACE link or code.');
  }

  const keyBytes = decodeSpaceCode(normalized);
  return { id: await getSpaceId(keyBytes), keyBytes, code: normalized.toUpperCase() };
}

async function makeInvite() {
  const keyBytes = crypto.getRandomValues(new Uint8Array(16));
  return { id: await getSpaceId(keyBytes), keyBytes, code: encodeSpaceCode(keyBytes) };
}

async function setEncryptionKey(keyBytes, id) {
  const material = await crypto.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveKey']);
  encryptionKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(id), info: new TextEncoder().encode('SPACE chat encryption v1') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  activateChatWhenReady();
}

function activateChatWhenReady() {
  if (chatReady || !encryptionKey || dataChannel?.readyState !== 'open') return;
  chatReady = true;
  messageInput.disabled = false;
  sendButton.disabled = false;
  roomTitle.textContent = 'Connected directly';
  setConnection(randomSession ? 'Direct connection · encrypted' : 'Direct connection · end-to-end encrypted', true);
  addSystemMessage(randomSession
    ? 'Messages are encrypted between browsers. Anonymous peer identity is not independently verified.'
    : 'Your messages are encrypted on this device before they are sent.');
  sendEncrypted({ type: 'hello', name: displayName });
  messageInput.focus();
}

function showNotice(text) {
  notice.textContent = text;
  notice.classList.add('is-visible');
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => notice.classList.remove('is-visible'), 2500);
}

function setConnection(text, connected = false) {
  connectionLabel.textContent = text;
  connectionState.classList.toggle('is-connected', connected);
}

function addSystemMessage(text) {
  const element = document.createElement('div');
  element.className = 'system-message';
  element.textContent = text;
  messages.append(element);
  messages.scrollTop = messages.scrollHeight;
}

function addChatMessage({ text, name, own = false, time = Date.now() }) {
  const article = document.createElement('article');
  article.className = `message${own ? ' own' : ''}`;
  const metadata = document.createElement('div');
  metadata.className = 'message-meta';
  const sender = document.createElement('span');
  sender.textContent = own ? 'YOU' : (name || 'GUEST');
  const timestamp = document.createElement('time');
  timestamp.dateTime = new Date(time).toISOString();
  timestamp.textContent = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }).format(time);
  metadata.append(sender, timestamp);
  const bubble = document.createElement('div');
  bubble.className = 'message-bubble';
  bubble.textContent = text;
  article.append(metadata, bubble);
  messages.append(article);
  messages.scrollTop = messages.scrollHeight;
}

async function sendEncrypted(payload) {
  if (!dataChannel || dataChannel.readyState !== 'open' || !encryptionKey) return;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encryptionKey, plaintext);
  dataChannel.send(JSON.stringify({ iv: encodeBase64Url(iv), data: encodeBase64Url(new Uint8Array(ciphertext)) }));
}

async function receiveEncrypted(raw) {
  try {
    const packet = JSON.parse(raw);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: decodeBase64Url(packet.iv) },
      encryptionKey,
      decodeBase64Url(packet.data),
    );
    const payload = JSON.parse(new TextDecoder().decode(plaintext));
    if (payload.type === 'hello') {
      roomTitle.textContent = `${payload.name || 'Someone'} joined`;
      addSystemMessage('A private, end-to-end encrypted connection is open.');
    } else if (payload.type === 'message' && typeof payload.text === 'string') {
      addChatMessage({ text: payload.text, name: payload.name, time: payload.time });
    }
  } catch {
    setConnection('Could not verify an encrypted message.', false);
  }
}

function setChannel(channel) {
  dataChannel = channel;
  dataChannel.onopen = activateChatWhenReady;
  dataChannel.onmessage = (event) => receiveEncrypted(event.data);
  dataChannel.onclose = () => {
    chatReady = false;
    messageInput.disabled = true;
    sendButton.disabled = true;
    if (chatView.classList.contains('is-hidden')) return;
    setConnection('The direct connection has closed.', false);
  };
}

function createPeerConnection() {
  if (peerConnection) return peerConnection;
  peerConnection = new RTCPeerConnection({
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
  });
  peerConnection.ondatachannel = (event) => setChannel(event.channel);
  peerConnection.onconnectionstatechange = () => {
    if (peerConnection.connectionState === 'failed') setConnection('Could not connect on this network. Try another network.', false);
  };
  return peerConnection;
}

function waitForIceGathering(connection) {
  if (connection.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, 8000);
    connection.addEventListener('icegatheringstatechange', () => {
      if (connection.iceGatheringState === 'complete') {
        clearTimeout(timeout);
        resolve();
      }
    }, { once: false });
  });
}

function signal(description) {
  if (socket?.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: 'signal', description }));
  }
}

async function startOffer() {
  const connection = createPeerConnection();
  setChannel(connection.createDataChannel('space-chat'));
  const offer = await connection.createOffer();
  await connection.setLocalDescription(offer);
  await waitForIceGathering(connection);
  signal(connection.localDescription);
}

async function acceptSignal(description) {
  const connection = createPeerConnection();
  await connection.setRemoteDescription(description);
  if (description.type === 'offer') {
    const answer = await connection.createAnswer();
    await connection.setLocalDescription(answer);
    await waitForIceGathering(connection);
    signal(connection.localDescription);
  }
}

function startCountdown(timestamp) {
  clearInterval(countdownTimer);
  expiresAt = timestamp;
  const tick = () => {
    const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    countdown.textContent = `${String(Math.floor(remaining / 60)).padStart(2, '0')}:${String(remaining % 60).padStart(2, '0')}`;
    if (remaining === 0) finishSession('Time is up. This space has disappeared.');
  };
  tick();
  countdownTimer = setInterval(tick, 1000);
}

function closeConnection() {
  clearInterval(countdownTimer);
  if (dataChannel && dataChannel.readyState !== 'closed') dataChannel.close();
  if (peerConnection) peerConnection.close();
  if (socket && socket.readyState < WebSocket.CLOSING) socket.close();
  dataChannel = null;
  peerConnection = null;
  socket = null;
  encryptionKey = null;
  ecdhKeyPair = null;
  pendingPeerPublicKey = null;
  chatReady = false;
  roomId = null;
}

function finishSession(message) {
  if (!chatView.classList.contains('is-hidden')) showNotice(message);
  closeConnection();
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
  chatView.classList.add('is-hidden');
  introView.classList.remove('is-hidden');
  messages.replaceChildren();
  inviteStrip.classList.remove('is-hidden');
  errorLabel.textContent = '';
  activeMatchRequestId = null;
  randomSession = false;
  setRandomSearchState(false, 'Choose a duration, then find someone new.');
  if (!lobbySocket) connectLobby();
}

function setRandomSearchState(searching, status) {
  findRandomButton.disabled = searching;
  cancelRandomButton.classList.toggle('is-hidden', !searching);
  document.querySelector('#create-button').disabled = searching;
  document.querySelector('#join-button').disabled = searching;
  inviteInput.disabled = searching;
  durationSelect.disabled = searching;
  randomDurationSelect.disabled = searching;
  randomStatus.textContent = status;
}

function sendMatchStart() {
  if (!lobbySocket || lobbySocket.readyState !== WebSocket.OPEN) return;
  beginMatchWhenConnected = false;
  lobbySocket.send(JSON.stringify({ type: 'match-start', duration: queuedMatchDuration }));
}

function startRandomSearch() {
  queuedMatchDuration = Number(randomDurationSelect.value);
  setRandomSearchState(true, 'Finding a random person in SPACE…');
  beginMatchWhenConnected = true;
  if (lobbySocket?.readyState === WebSocket.OPEN) sendMatchStart();
  else connectLobby();
}

function connectLobby() {
  if (pageLeaving || (lobbySocket && lobbySocket.readyState < WebSocket.CLOSING)) return;
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const candidate = new WebSocket(`${protocol}//${window.location.host}`);
  lobbySocket = candidate;
  candidate.addEventListener('open', () => {
    if (beginMatchWhenConnected) sendMatchStart();
  });
  candidate.addEventListener('message', async (event) => {
    let message;
    try { message = JSON.parse(event.data); } catch { return; }
    if (message.type === 'match-count') {
      availableCount.textContent = String(message.count);
    } else if (message.type === 'match-waiting') {
      setRandomSearchState(true, 'You’re in the SPACE queue. Waiting for another person…');
    } else if (message.type === 'request-sent') {
      setRandomSearchState(true, 'Request sent. Waiting for them to accept…');
    } else if (message.type === 'match-request') {
      activeMatchRequestId = message.requestId;
      setRandomSearchState(false, 'Someone wants to connect with you.');
      matchRequestDetails.textContent = `A random person wants to chat for ${message.duration} minutes. Accept to connect directly.`;
      matchDialog.showModal();
    } else if (message.type === 'request-declined' || message.type === 'request-expired') {
      setRandomSearchState(true, message.type === 'request-expired'
        ? 'No response. Waiting for another compatible person…'
        : 'They passed. Waiting for another compatible person…');
    } else if (message.type === 'request-canceled') {
      setRandomSearchState(true, 'That person disconnected. Waiting for another compatible person…');
    } else if (message.type === 'request-dismissed') {
      activeMatchRequestId = null;
      setRandomSearchState(false, 'Request closed. You can try again when ready.');
    } else if (message.type === 'match-canceled') {
      setRandomSearchState(false, 'Search canceled.');
    } else if (message.type === 'match-ready') {
      await beginRandomSession(candidate, message);
    } else if (message.type === 'match-key') {
      if (ecdhKeyPair) await receiveRandomPublicKey(message.publicKey);
      else pendingPeerPublicKey = message.publicKey;
    } else if (message.type === 'signal') {
      try { await acceptSignal(message.description); } catch { setConnection('Could not verify the connection setup.', false); }
    } else if (message.type === 'peer-left') {
      finishSession('The other person left. The space is closed.');
    } else if (message.type === 'session-ended') {
      finishSession('This space has ended.');
    }
  });
  candidate.addEventListener('error', () => {
    if (!chatView.classList.contains('is-hidden')) return;
    availableCount.textContent = '—';
    if (randomStatus) randomStatus.textContent = 'Could not reach the matching service.';
  });
  candidate.addEventListener('close', () => {
    if (pageLeaving) return;
    if (socket === candidate && randomSession) {
      finishSession('The space connection closed.');
      return;
    }
    if (lobbySocket !== candidate) return;
    lobbySocket = null;
    availableCount.textContent = '—';
    if (beginMatchWhenConnected || !cancelRandomButton.classList.contains('is-hidden') || matchDialog.open) {
      beginMatchWhenConnected = false;
      activeMatchRequestId = null;
      if (matchDialog.open) matchDialog.close();
      setRandomSearchState(false, 'Connection lost. Tap Find to search again.');
    }
    if (!chatView.classList.contains('is-hidden')) return;
    setTimeout(connectLobby, 1500);
  });
}

async function receiveRandomPublicKey(encodedKey) {
  const publicKey = await crypto.subtle.importKey(
    'raw',
    decodeBase64Url(encodedKey),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, ecdhKeyPair.privateKey, 256);
  await setEncryptionKey(new Uint8Array(sharedSecret), roomId);
}

async function beginRandomSession(activeSocket, message) {
  lobbySocket = null;
  socket = activeSocket;
  roomId = message.room;
  randomSession = true;
  chatReady = false;
  displayName = nameInput.value.trim() || 'Guest';
  introView.classList.add('is-hidden');
  chatView.classList.remove('is-hidden');
  inviteStrip.classList.add('is-hidden');
  messages.replaceChildren();
  addSystemMessage('You’re chatting with a random person. Keep personal details private.');
  roomTitle.textContent = 'Connecting to your match';
  setConnection('Creating an encrypted peer connection…');
  messageInput.disabled = true;
  sendButton.disabled = true;
  startCountdown(message.expiresAt);

  try {
    ecdhKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', ecdhKeyPair.publicKey));
    socket.send(JSON.stringify({ type: 'match-key', publicKey: encodeBase64Url(publicKey) }));
    if (pendingPeerPublicKey) {
      const pendingKey = pendingPeerPublicKey;
      pendingPeerPublicKey = null;
      await receiveRandomPublicKey(pendingKey);
    }
    if (message.initiator) await startOffer();
  } catch {
    setConnection('Could not secure this connection. Please end the space.', false);
  }
}

function connectToRoom({ id, keyBytes, code, host = false, duration = 15 }) {
  roomId = id;
  joinedAsHost = host;
  randomSession = false;
  chatReady = false;
  displayName = nameInput.value.trim() || 'Guest';
  const shareCode = code || 'Waiting for the space code';
  const shareUrl = getInviteUrl(shareCode === 'Waiting for the space code' ? code : shareCode);
  updateInviteUrl(shareCode === 'Waiting for the space code' ? null : shareCode);
  setEncryptionKey(keyBytes, id).then(() => {
    introView.classList.add('is-hidden');
    chatView.classList.remove('is-hidden');
    messages.replaceChildren();
    roomTitle.textContent = host ? 'Waiting for someone' : 'Joining private space';
    inviteAddress.href = shareUrl;
    inviteAddress.textContent = shareUrl;
    inviteLink.href = shareUrl;
    inviteLink.textContent = 'Open space';
    inviteStrip.classList.toggle('is-hidden', !host);
    setConnection('Making a private connection…');
    messageInput.disabled = true;
    sendButton.disabled = true;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    socket = new WebSocket(`${protocol}//${window.location.host}`);
    socket.addEventListener('open', () => {
      socket.send(JSON.stringify({ type: 'join', room: roomId, duration }));
    });
    socket.addEventListener('message', async (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === 'joined') {
        startCountdown(message.expiresAt);
        if (!message.initiator) roomTitle.textContent = 'Waiting for a direct connection';
      } else if (message.type === 'peer-joined') {
        roomTitle.textContent = 'Connecting directly';
        try { await startOffer(); } catch { setConnection('Could not start a direct connection.', false); }
      } else if (message.type === 'signal') {
        try { await acceptSignal(message.description); } catch { setConnection('Could not verify the connection setup.', false); }
      } else if (message.type === 'peer-left') {
        finishSession('The other person left. The space is closed.');
      } else if (message.type === 'session-ended') {
        finishSession('This space has ended.');
      } else if (message.type === 'room-full') {
        finishSession('This space already has two people.');
      }
    });
    socket.addEventListener('error', () => setConnection('Could not reach the space service.', false));
    socket.addEventListener('close', () => {
      if (!chatView.classList.contains('is-hidden')) setConnection('The space connection has closed.', false);
    });
  }).catch(() => {
    errorLabel.textContent = 'Secure encryption is not available in this browser context. Open SPACE over HTTPS or localhost.';
  });
}

document.querySelector('#create-button').addEventListener('click', async () => {
  errorLabel.textContent = '';
  if (!window.isSecureContext || !crypto.subtle) {
    errorLabel.textContent = 'Secure encryption needs HTTPS. On this device, use localhost.';
    return;
  }
  try {
    const invite = await makeInvite();
    updateInviteUrl(invite.code);
    connectToRoom({ ...invite, host: true, duration: Number(durationSelect.value) });
  } catch {
    errorLabel.textContent = 'Could not create a secure SPACE code. Please try again.';
  }
});

document.querySelector('#join-button').addEventListener('click', async () => {
  errorLabel.textContent = '';
  if (!window.isSecureContext || !crypto.subtle) {
    errorLabel.textContent = 'Secure encryption needs HTTPS. On this device, use localhost.';
    return;
  }
  try {
    const invite = await parseInvite(inviteInput.value);
    updateInviteUrl(invite.code);
    connectToRoom(invite);
  } catch (error) {
    errorLabel.textContent = error.message;
  }
});

findRandomButton.addEventListener('click', startRandomSearch);

cancelRandomButton.addEventListener('click', () => {
  beginMatchWhenConnected = false;
  if (lobbySocket?.readyState === WebSocket.OPEN) {
    lobbySocket.send(JSON.stringify({ type: 'match-cancel' }));
  }
  setRandomSearchState(false, 'Search canceled.');
});

function respondToMatch(accept) {
  if (!activeMatchRequestId || lobbySocket?.readyState !== WebSocket.OPEN) return;
  lobbySocket.send(JSON.stringify({ type: 'match-respond', requestId: activeMatchRequestId, accept }));
  activeMatchRequestId = null;
  matchDialog.close();
  setRandomSearchState(false, accept ? 'Accepted. Connecting…' : 'Request declined.');
}

document.querySelector('#accept-match-button').addEventListener('click', () => respondToMatch(true));
document.querySelector('#decline-match-button').addEventListener('click', () => respondToMatch(false));
matchDialog.addEventListener('cancel', (event) => {
  event.preventDefault();
  respondToMatch(false);
});

inviteInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') document.querySelector('#join-button').click();
});

document.querySelector('#copy-button').addEventListener('click', async () => {
  const shareUrl = inviteAddress.href || getInviteUrl(inviteAddress.textContent.trim());
  try {
    await navigator.clipboard.writeText(shareUrl);
    document.querySelector('#copy-label').textContent = 'Copied';
    showNotice('SPACE link copied. Share it only with your person.');
    setTimeout(() => { document.querySelector('#copy-label').textContent = 'Copy link'; }, 1800);
  } catch {
    showNotice('Copy is unavailable here. Select and copy the share link.');
  }
});

inviteAddress.addEventListener('click', (event) => {
  event.preventDefault();
  window.open(inviteAddress.href, '_blank', 'noopener,noreferrer');
});

inviteLink.addEventListener('click', async (event) => {
  event.preventDefault();
  const shareUrl = inviteLink.href || getInviteUrl(inviteAddress.textContent.trim());
  try {
    await navigator.clipboard.writeText(shareUrl);
    showNotice('Share link copied. Paste it into any browser to continue the chat.');
    window.open(shareUrl, '_blank', 'noopener,noreferrer');
  } catch {
    window.open(shareUrl, '_blank', 'noopener,noreferrer');
  }
});

document.querySelector('#message-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !dataChannel || dataChannel.readyState !== 'open') return;
  const time = Date.now();
  try {
    await sendEncrypted({ type: 'message', text, name: displayName, time });
    addChatMessage({ text, own: true, time });
    messageInput.value = '';
  } catch {
    showNotice('Message could not be sent.');
  }
});

document.querySelector('#end-button').addEventListener('click', () => {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'end' }));
  finishSession('Space ended. The conversation is gone.');
});

document.querySelector('#back-button').addEventListener('click', () => {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'end' }));
  finishSession('Space ended.');
});

document.querySelector('#privacy-button').addEventListener('click', () => privacyDialog.showModal());
privacyDialog.addEventListener('click', (event) => {
  if (event.target === privacyDialog) privacyDialog.close();
});

window.addEventListener('pagehide', () => {
  pageLeaving = true;
  clearInterval(countdownTimer);
  if (dataChannel) dataChannel.close();
  if (peerConnection) peerConnection.close();
  if (socket) socket.close();
  if (lobbySocket) lobbySocket.close();
});

(async () => {
  const spaceParam = new URLSearchParams(window.location.search).get('space');
  if (!spaceParam) return;
  try {
    const invite = await parseInvite(spaceParam);
    connectToRoom(invite);
  } catch (error) {
    errorLabel.textContent = error.message;
  }
})();

connectLobby();
