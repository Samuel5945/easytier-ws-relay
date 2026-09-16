import { Buffer } from 'buffer';
import { parseHeader } from './core/packet.js';
import { PacketType, HEADER_SIZE, MY_PEER_ID } from './core/constants.js';
import { loadProtos } from './core/protos.js';
import { handleHandshake, handlePing, handleForwarding } from './core/basic_handlers.js';
import { handleRpcReq, handleRpcResp } from './core/rpc_handler.js';
import { PeerManager } from './core/peer_manager.js';
import { randomU64String } from './core/crypto.js';

// Stale-socket pruning: how often to check, and how long a silent client may
// stay before its socket is considered dead and removed from the peer table.
const STALE_CHECK_MS = 60_000;
const STALE_TIMEOUT_MS = 150_000;
// Do not rewrite the hibernation attachment on every packet; 30s granularity is
// plenty for a 150s staleness threshold.
const ATTACHMENT_REFRESH_MS = 30_000;

export class RelayRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.types = loadProtos();
    // Per-instance state. The module singleton outlives DO instances inside an
    // isolate; reusing it would keep stale WebSocket handles from a previous
    // instance and trigger "Cannot perform I/O on behalf of a different
    // Durable Object" on forwarding.
    this.peerManager = new PeerManager();
    this.peerManager.setTypes(this.types);
    this.networkDigestRegistry = new Map();
    this.peerCenterStateByGroup = new Map();

    // Restore sockets after hibernation to keep metadata
    this.state.getWebSockets().forEach((ws) => this._restoreSocket(ws));

    // Periodic stale-socket pruning. A killed client leaves its WebSocket
    // behind (its close is never delivered), so the relay would keep
    // broadcasting the dead peer as a second node with the same virtual IP.
    this.state.storage.setAlarm(Date.now() + STALE_CHECK_MS).catch(() => { });
  }

  // Prune sockets whose client stopped sending. Live EasyTier clients ping
  // every few seconds, so a silent socket means the process is gone.
  async alarm() {
    const now = Date.now();
    let pruned = 0;
    for (const ws of this.state.getWebSockets()) {
      const meta = ws.deserializeAttachment ? (ws.deserializeAttachment() || {}) : {};
      const last = ws.lastSeen || meta.lastSeen || 0;
      if (last && now - last > STALE_TIMEOUT_MS) {
        try { this.peerManager.removePeer(ws); } catch (_) { }
        try { ws.close(1000, 'stale'); } catch (_) { }
        pruned++;
      }
    }
    if (pruned) {
      console.log(`[alarm] pruned ${pruned} stale socket(s)`);
      try {
        this.peerManager.broadcastRouteUpdate(this.types, undefined, undefined, { forceFull: true });
      } catch (_) { }
    }
    this.state.storage.setAlarm(Date.now() + STALE_CHECK_MS).catch(() => { });
  }

  async fetch(request) {
    const url = new URL(request.url);
    const wsPath = '/' + this.env.WS_PATH || '/ws';
    if (url.pathname !== wsPath) {
      return new Response('Not found', { status: 404 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected websocket', { status: 400 });
    }

    const pair = new WebSocketPair();
    const server = pair[1];
    const client = pair[0];
    await this.handleSession(server);

    return new Response(null, { status: 101, webSocket: client });
  }

  async handleSession(webSocket) {
    this.state.acceptWebSocket(webSocket);
    this._initSocket(webSocket);
  }

  async webSocketMessage(ws, message) {
    try {
      let buffer = null;
      if (message instanceof ArrayBuffer) {
        buffer = Buffer.from(message);
      } else if (message instanceof Uint8Array) {
        buffer = Buffer.from(message);
      } else if (ArrayBuffer.isView(message) && message.buffer) {
        buffer = Buffer.from(message.buffer);
      } else {
        console.warn('[ws] unsupported message type', typeof message);
        return;
      }
      console.log(`[ws] recv len=${buffer.length}`);
      ws.lastSeen = Date.now();
      this._refreshAttachment(ws);
      const header = parseHeader(buffer);
      if (!header) {
        console.error('[ws] parseHeader failed, raw hex=', buffer.toString('hex'));
        return;
      }
      console.log(`[ws] header from=${header.fromPeerId} to=${header.toPeerId} type=${header.packetType} len=${header.len}`);
      const payload = buffer.subarray(HEADER_SIZE);
      switch (header.packetType) {
        case PacketType.HandShake:
          console.log(`[ws] -> handleHandshake payload hex=${payload.toString('hex')}`);
          handleHandshake(ws, header, payload, this.types, this.peerManager, this.networkDigestRegistry);
          break;
        case PacketType.Ping:
          handlePing(ws, header, payload);
          break;
        case PacketType.RpcReq:
          if (header.toPeerId !== PacketType.Invalid && header.toPeerId !== undefined && header.toPeerId !== null && header.toPeerId !== 0 && header.toPeerId !== PacketType.Invalid && header.toPeerId !== undefined && header.toPeerId !== null && header.toPeerId !== 0 && header.toPeerId !== PacketType.Invalid) {
            // fallthrough handled below; guard keeps eslint quiet
          }
          if (header.toPeerId === PacketType.Invalid /* never true */) {
            // no-op
          }
          if (header.toPeerId === undefined || header.toPeerId === null) {
            handleRpcReq(ws, header, payload, this.types, this.peerManager, this.peerCenterStateByGroup);
            break;
          }
          if (header.toPeerId === MY_PEER_ID) {
            handleRpcReq(ws, header, payload, this.types, this.peerManager, this.peerCenterStateByGroup);
            break;
          }
          handleForwarding(ws, header, buffer, this.types, this.peerManager);
          break;
        case PacketType.RpcResp:
          if (header.toPeerId === undefined || header.toPeerId === null || header.toPeerId === MY_PEER_ID) {
            handleRpcResp(ws, header, payload, this.types, this.peerManager);
            break;
          }
          // If toPeerId is not MY_PEER_ID, forward to the target peer
          if (header.packetType !== PacketType.Data) {
            console.log(`[ws] -> forward RpcResp type=${header.packetType} from=${header.fromPeerId} to=${header.toPeerId} len=${payload.length}`);
          }
          handleForwarding(ws, header, buffer, this.types, this.peerManager);
          break;
        case PacketType.Data:
        default:
          if (header.packetType !== PacketType.Data) {
            console.log(`[ws] -> forward type=${header.packetType} len=${payload.length}`);
          }
          handleForwarding(ws, header, buffer, this.types, this.peerManager);
      }
    } catch (e) {
      console.error('relay_room message handling error:', e);
      try { ws.close(1011, 'internal error'); } catch (_) { }
    }
  }

  async webSocketClose(ws) {
    if (ws.peerId) {
      const groupKey = ws.groupKey;
      const removed = this.peerManager.removePeer(ws);
      if (removed) {
        try {
          this.peerManager.broadcastRouteUpdate(this.types, groupKey);
        } catch (_) { }
      }
    }
  }

  async webSocketError(ws) {
    await this.webSocketClose(ws);
  }

  _initSocket(ws, meta = {}) {
    ws.peerId = meta.peerId || null;
    ws.groupKey = meta.groupKey || null;
    ws.domainName = meta.domainName || null;
    // Keep the last activity time the client reported; a restored socket must
    // not look freshly active or stale pruning would never fire.
    ws.lastSeen = meta.lastSeen || Date.now();
    ws.attachmentWrittenAt = Date.now();
    ws.serverSessionId = meta.serverSessionId || randomU64String();
    ws.weAreInitiator = false;
    ws.crypto = { enabled: false };
    this._writeAttachment(ws);
  }

  _writeAttachment(ws) {
    ws.serializeAttachment?.({
      peerId: ws.peerId,
      groupKey: ws.groupKey,
      domainName: ws.domainName,
      serverSessionId: ws.serverSessionId,
      lastSeen: ws.lastSeen,
    });
    ws.attachmentWrittenAt = Date.now();
  }

  // Persist lastSeen occasionally so staleness survives hibernation, without
  // paying a serialization cost on every packet.
  _refreshAttachment(ws) {
    if (Date.now() - (ws.attachmentWrittenAt || 0) < ATTACHMENT_REFRESH_MS) return;
    this._writeAttachment(ws);
  }

  _restoreSocket(ws) {
    const meta = ws.deserializeAttachment ? (ws.deserializeAttachment() || {}) : {};
    this._initSocket(ws, meta);
    
    if (ws.peerId && ws.groupKey) {
      this.peerManager.addPeer(ws.peerId, ws);
    }
  }
}
