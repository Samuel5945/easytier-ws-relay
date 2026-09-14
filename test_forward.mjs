import { PeerManager } from './src/worker/core/peer_manager.js';
import { handleForwarding } from './src/worker/core/basic_handlers.js';
import { createHeader } from './src/worker/core/packet.js';
import { loadProtos } from './src/worker/core/protos.js';
import { PacketType } from './src/worker/core/constants.js';

const types = loadProtos();
const pm = new PeerManager();
pm.setTypes(types);

function fakeWs(peerId) {
  return { peerId, groupKey: 'g', readyState: 1, sent: [], send(b) { this.sent.push(Buffer.from(b)); } };
}
const A = fakeWs(111), B = fakeWs(333);
pm.addPeer(111, A);
pm.addPeer(333, B);

const ip = (s) => s.split('.').reduce((a, o) => ((a << 8) | +o) >>> 0, 0) >>> 0;
function ipPacket(src, dst) {
  const p = Buffer.alloc(20);
  p[0] = 0x45;
  p.writeUInt16BE(20, 2); // total length; looksLikeIpv4 validates it
  p.writeUInt32BE(src, 12);
  p.writeUInt32BE(dst, 16);
  return p;
}
function dataMsg(from, to, src, dst) {
  const payload = ipPacket(ip(src), ip(dst));
  const h = createHeader(from, to, PacketType.Data, payload.length);
  return [Buffer.concat([h, payload]), { fromPeerId: from, toPeerId: to, packetType: PacketType.Data, len: payload.length }];
}
// Seed authoritative reported addresses for A and B.
pm.updatePeerInfo('g', 111, { peerId: 111, ipv4Addr: { addr: ip('10.144.144.2') }, networkLength: 24, version: 1 });
pm.updatePeerInfo('g', 333, { peerId: 333, ipv4Addr: { addr: ip('10.144.144.3') }, networkLength: 24, version: 1 });

// 1. 按 peer id 正常投递
let [m1, h1] = dataMsg(333, 111, '10.144.144.3', '10.144.144.2');
handleForwarding(B, h1, m1, types, pm);
console.log('T1 按 peer id 投递:', A.sent.some(b => b.equals(m1)));

// 2. 旧 peer id + 明文目的 IP -> 按地址兜底投递
const before = B.sent.length;
let [m2, h2] = dataMsg(111, 222, '10.144.144.2', '10.144.144.3');
handleForwarding(A, h2, m2, types, pm);
console.log('T2 旧 ID 按目的 IP 兜底投递:', B.sent.length === before + 1);

// 3. 未上报地址的新 peer 发合法私网包 -> 被学习并可作为投递目标
const C = fakeWs(555);
pm.addPeer(555, C);
let [m3, h3] = dataMsg(555, 111, '10.144.144.9', '10.144.144.2');
handleForwarding(C, h3, m3, types, pm);
console.log('T3 合法私网源地址被学习:', pm.getPeerIdByIp('g', ip('10.144.144.9')) === 555);

// 4. 公网源地址（密文误判/脏数据特征）不被学习
let [m4, h4] = dataMsg(555, 111, '80.207.42.254', '10.144.144.2');
handleForwarding(C, h4, m4, types, pm);
console.log('T4 公网源地址不被学习:', pm.getPeerIdByIp('g', ip('80.207.42.254')) === null);

// 5. 上报地址拥有最高权威：嗅探不得覆盖
const D = fakeWs(777);
pm.addPeer(777, D);
pm.updatePeerInfo('g', 777, { peerId: 777, ipv4Addr: { addr: ip('10.144.144.7') }, networkLength: 24, version: 1 });
let [m5, h5] = dataMsg(777, 111, '10.144.144.99', '10.144.144.2');
handleForwarding(D, h5, m5, types, pm);
console.log('T5 嗅探不覆盖上报地址:', pm.getPeerIdByIp('g', ip('10.144.144.7')) === 777 && pm.getPeerIdByIp('g', ip('10.144.144.99')) === null);

// 6. 密文样载荷（非合法 IP 头）既不投递也不学习
const cipher = Buffer.alloc(24, 0xab);
const hC = { fromPeerId: 555, toPeerId: 999, packetType: PacketType.Data, len: cipher.length };
const aBefore = A.sent.length, bBefore = B.sent.length;
handleForwarding(C, hC, Buffer.concat([createHeader(555, 999, PacketType.Data, cipher.length), cipher]), types, pm);
console.log('T6 密文载荷被安全忽略:', A.sent.length === aBefore && B.sent.length === bBefore && pm.getPeerIdByIp('g', ip('171.171.171.171')) === null);

// 7. 路由广播正常发出
A.sent.length = 0; B.sent.length = 0;
pm.broadcastRouteUpdate(types, 'g', undefined, { forceFull: true });
console.log('T7 广播发出消息:', A.sent.length > 0 && B.sent.length > 0);
