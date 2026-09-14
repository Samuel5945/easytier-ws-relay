import { MAGIC, VERSION, MY_PEER_ID, PacketType, HEADER_SIZE } from './constants.js';
import { createHeader } from './packet.js';
import { wrapPacket, randomU64String } from './crypto.js';

const WS_OPEN = (typeof WebSocket !== 'undefined' && WebSocket.OPEN) ? WebSocket.OPEN : 1;

// Strict check that a Data payload is a plaintext IPv4 packet from the virtual
// NIC. Encrypted/compressed or otherwise non-tunnel payloads must never be
// mistaken for one: a mislearned source address poisons every route broadcast.
function looksLikeIpv4(p) {
  if (p.length < 20) return false;
  if ((p[0] >> 4) !== 4) return false;
  const ihl = p[0] & 0x0f;
  if (ihl < 5 || ihl > 15) return false;
  if (p.readUInt16BE(2) !== p.length) return false;
  const src = p.readUInt32BE(12);
  const dst = p.readUInt32BE(16);
  if (src === 0 || dst === 0 || src === dst) return false;
  return isPrivateU32(src);
}

// Virtual addresses are private ranges; a public-looking source is not tunnel traffic.
function isPrivateU32(ip) {
  const a = ip >>> 24;
  const b = (ip >>> 16) & 0xff;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

// pm and registry are owned by the RelayRoom Durable Object instance.
// They must NOT come from module-level singletons: the module scope outlives
// DO instances inside an isolate, and reusing a previous instance's WebSocket
// throws "Cannot perform I/O on behalf of a different Durable Object".
export function handleHandshake(ws, header, payload, types, pm, networkDigestRegistry) {
  try {
    const req = types.HandshakeRequest.decode(payload);
    try {
      const dig = req.networkSecretDigrest ? Buffer.from(req.networkSecretDigrest) : Buffer.alloc(0);
      console.log(`Handshake networkSecretDigest(hex)=${dig.toString('hex')}`);
    } catch (_) {
      // ignore
    }

    if (req.magic !== MAGIC) {
      console.error('Invalid magic');
      ws.close();
      return;
    }

    const clientNetworkName = req.networkName || '';
    const clientDigest = req.networkSecretDigrest ? Buffer.from(req.networkSecretDigrest) : Buffer.alloc(0);
    const digestHex = clientDigest.toString('hex');
    const existingDigest = networkDigestRegistry.get(clientNetworkName);
    if (existingDigest && existingDigest !== digestHex) {
      console.error(`Rejecting handshake from ${req.myPeerId}: digest mismatch for network "${clientNetworkName}" (existing=${existingDigest}, incoming=${digestHex})`);
      ws.close();
      return;
    }
    if (!existingDigest) {
      networkDigestRegistry.set(clientNetworkName, digestHex);
    }
    const groupDigest = networkDigestRegistry.get(clientNetworkName) || '';
    const groupKey = `${clientNetworkName}:${groupDigest}`;
    const serverNetworkName = process.env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME || 'public_server';
    const digest = new Uint8Array(32);

    ws.domainName = clientNetworkName;

    const respPayload = {
      magic: MAGIC,
      myPeerId: MY_PEER_ID,
      version: VERSION,
      features: ["node-server-v1"],
      networkName: serverNetworkName,
      networkSecretDigrest: digest
    };

    ws.groupKey = groupKey;
    ws.peerId = req.myPeerId;
    pm.addPeer(req.myPeerId, ws);
    pm.updatePeerInfo(ws.groupKey, req.myPeerId, {
      peerId: req.myPeerId,
      version: 1,
      lastUpdate: { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
      instId: { part1: 0, part2: 0, part3: 0, part4: 0 },
      networkLength: Number(process.env.EASYTIER_NETWORK_LENGTH || 24),
    });
    pm.setPublicServerFlag(true);
    ws.crypto = { enabled: false };

    const respBuffer = types.HandshakeRequest.encode(respPayload).finish();
    const respHeader = createHeader(MY_PEER_ID, req.myPeerId, PacketType.HandShake, respBuffer.length);
    ws.send(Buffer.concat([respHeader, Buffer.from(respBuffer)]));
    if (!ws.serverSessionId) {
      ws.serverSessionId = randomU64String();
    }
    if (ws.weAreInitiator === undefined) {
      ws.weAreInitiator = false;
    }
    // Persist identity in the hibernation attachment so that after the DO
    // instance is evicted and recreated, _restoreSocket can re-register this
    // connection in the new instance's PeerManager.
    try {
      ws.serializeAttachment?.({
        peerId: ws.peerId,
        groupKey: ws.groupKey,
        domainName: ws.domainName,
        serverSessionId: ws.serverSessionId,
      });
    } catch (_) { }

    setTimeout(() => {
      try {
        if (ws.readyState === WS_OPEN) {
          pm.pushRouteUpdateTo(req.myPeerId, ws, types, { forceFull: true });
          pm.broadcastRouteUpdate(types, ws.groupKey, req.myPeerId, { forceFull: true });
        }
      } catch (e) {
        console.error(`Failed to push initial route update to ${req.myPeerId}:`, e.message);
      }
    }, 50);

  } catch (e) {
    console.error('Handshake error:', e);
    ws.close();
  }
}

export function handlePing(ws, header, payload) {
  const msg = wrapPacket(createHeader, MY_PEER_ID, header.fromPeerId, PacketType.Pong, payload, ws);
  ws.send(msg);
}

export function handleForwarding(sourceWs, header, fullMessage, types, pm) {
  const groupKey = sourceWs && sourceWs.groupKey;
  const payload = fullMessage.subarray(HEADER_SIZE);

  // Virtual IPs come only from client route-sync reports (updatePeerInfo).
  // Relayed Data payloads are end-to-end encrypted, so sniffing addresses
  // from them would learn ciphertext garbage and poison route broadcasts.
  const isIpv4Packet = header.packetType === PacketType.Data && looksLikeIpv4(payload);

  let targetPeerId = header.toPeerId;
  let targetWs = pm.getPeerWs(targetPeerId, groupKey);

  // Clients keep sending to a peer's previous peer id after it reconnects with
  // a new one; fall back to resolving the destination by reported virtual IP.
  if ((!targetWs || targetWs.readyState !== WS_OPEN) && isIpv4Packet) {
    const dstIp = payload.readUInt32BE(16);
    const altPeerId = pm.getPeerIdByIp(groupKey, dstIp);
    if (altPeerId !== null && altPeerId !== targetPeerId) {
      targetPeerId = altPeerId;
      targetWs = pm.getPeerWs(targetPeerId, groupKey);
    }
  }

  if (targetWs && targetWs.readyState === WS_OPEN) {
    const srcGroup = groupKey;
    const dstGroup = targetWs && targetWs.groupKey;
    if (srcGroup && dstGroup && srcGroup !== dstGroup) {
      return;
    }
    try {
      targetWs.send(fullMessage);
    } catch (e) {
      console.error(`Forward to ${targetPeerId} failed: ${e.message}`);
      pm.removePeer(targetWs);
      try {
        pm.broadcastRouteUpdate(types, srcGroup);
      } catch (err) {
        console.error(`Broadcast after forward failure failed: ${err.message}`);
      }
    }
  }
}
