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
  p.writeUInt32BE(src, 12);
  p.writeUInt32BE(dst, 16);
  return p;
}
function dataMsg(from, to, src, dst) {
  const payload = ipPacket(ip(src), ip(dst));
  const h = createHeader(from, to, PacketType.Data, payload.length);
  return [Buffer.concat([h, payload]), { fromPeerId: from, toPeerId: to, packetType: PacketType.Data, len: payload.length }];
}

// 1. A 发数据到 B 的旧 ID(222)，目的 IP 未学习 -> 数据不投递，但学到 A 的 IP
let [m1, h1] = dataMsg(111, 222, '10.144.144.2', '10.144.144.3');
handleForwarding(A, h1, m1, types, pm);
console.log('T1 A 的虚拟 IP 被学习:', pm.getPeerIdByIp('g', ip('10.144.144.2')) === 111);
console.log('T2 目的未学习时数据不投递:', !B.sent.some(b => b.equals(m1)));

// 2. B 发数据（源 .3）-> 学到 B 的 IP，且 A 正常收到
let [m2, h2] = dataMsg(333, 111, '10.144.144.3', '10.144.144.2');
handleForwarding(B, h2, m2, types, pm);
console.log('T3 B 的虚拟 IP 被学习:', pm.getPeerIdByIp('g', ip('10.144.144.3')) === 333);
console.log('T4 A 收到 B 的包:', A.sent.length > 0);

// 3. A 再发旧 ID 222 -> 按目的 IP 兜底解析到 333 并投递
const before = B.sent.length;
handleForwarding(A, h1, m1, types, pm);
console.log('T5 旧 ID 按目的 IP 兜底投递:', B.sent.length === before + 1);

// 4. 路由广播里应包含带 IP 的 peer 信息（pushRouteUpdateTo 不抛错且发出内容）
A.sent.length = 0;
pm.broadcastRouteUpdate(types, 'g', undefined, { forceFull: true });
console.log('T6 广播发出消息:', A.sent.length > 0 && B.sent.length > 0);
