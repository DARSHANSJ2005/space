# SPACE

SPACE is a temporary, two-person chat. Messages are encrypted in each browser with AES-GCM and sent over a WebRTC data channel. Random matches derive an ephemeral shared key with ECDH; the private key is non-exportable. The Node server keeps rooms and matchmaking state in memory and relays WebRTC setup descriptions and ECDH public keys, but it does not receive chat messages or write them to a database.

## Run locally

```sh
npm install
npm start
```

Open `http://localhost:3000`. Create a space, choose its lifetime, and share the grouped 26-character SPACE code with one person. The code is a 128-bit secret used to identify the space and derive the encryption key locally; the signaling server never receives it. Treat the code like a password. Either participant can end the space; spaces also expire automatically.

For random matching, choose a session duration and select **Find random person in our SPACE**. You enter an in-memory queue without supplying profile details. The other person must accept before a session starts; requests expire after 30 seconds. The requester-selected duration applies to both participants.

## Deploy

Put the Node server behind an HTTPS reverse proxy and forward WebSocket upgrades. The browser requires a secure context for Web Crypto and WebRTC; the client automatically uses WSS when the site is served over HTTPS. The server listens on port `3000` by default and supports the `PORT` environment variable.

## Limits to understand

- An IP address by itself cannot reliably connect browsers across NAT and firewalls. SPACE shares a room URL instead; the small in-memory signaling service is required to introduce the peers.
- WebRTC uses a public STUN service for connection discovery. STUN and network providers may see IP addresses. Some network combinations require a TURN relay, which is not included here.
- Chat messages are not saved by this app, but this is not a guarantee of perfect security. Recipients can copy or capture messages, and browser/device compromise is outside the app's protection.
- Anyone who receives the SPACE code can join and derive the encryption key. Share it only with the intended person.
- Random matching uses an in-memory queue on one Node process. The availability count is per process, not a global count across multiple server instances. No intention, gender, or location profile is collected; random peers are anonymous and their identity is not independently verified.