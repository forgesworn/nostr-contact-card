import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

/** forgesworn-link SPEC.md §2: the domain prefix a card signature covers. */
const DOMAIN = concatBytes(utf8ToBytes('forgesworn-link/card/v1'), new Uint8Array([0]))
export const LINK_CARD_MAX = 4096
export const LINK_CARD_MIN = 126
export const LINK_CARD_MAX_AGE = 604800

export interface LinkHint { kind: number; value: Uint8Array }
export interface LinkCard {
  nodeId: string
  issuedAt: number
  expiresAt: number
  serial: number
  hints: LinkHint[]
  /** Relay hints (kind 0x01) as URLs. */
  relays: string[]
  /** Onion hints (kind 0x03) as `host.onion:port`. */
  onions: string[]
}

export type LinkVerdict = { ok: true; card: LinkCard } | { ok: false; rule: number; reason: string }

/**
 * Verify an FSL-CARD-1 by SPEC §2.3 rules 1 to 8. Rule 9, the expected node
 * id, is the contact card's business and is applied by `readCard`. Rule 8,
 * the serial, needs the highest serial previously accepted, which the
 * caller passes when it has one.
 */
export function verifyLinkCard(bytes: Uint8Array, now: number, highestSerial?: number): LinkVerdict {
  if (bytes.length < LINK_CARD_MIN || bytes.length > LINK_CARD_MAX) return { ok: false, rule: 1, reason: 'length' }
  if (String.fromCharCode(...bytes.subarray(0, 4)) !== 'FSL1' || bytes[4] !== 1) return { ok: false, rule: 2, reason: 'magic or version' }
  const count = bytes[61]!
  if (count > 16) return { ok: false, rule: 3, reason: 'hint count' }
  const end = bytes.length - 64
  let off = 62
  const hints: LinkHint[] = []
  for (let i = 0; i < count; i++) {
    if (off + 3 > end) return { ok: false, rule: 3, reason: 'hint runs past the signature' }
    const kind = bytes[off]!, len = (bytes[off + 1]! << 8) | bytes[off + 2]!
    if (kind === 0x01 && (len === 0 || len > 255)) return { ok: false, rule: 3, reason: 'relay hint length' }
    if (kind === 0x02 && len !== 18) return { ok: false, rule: 3, reason: 'udp hint length' }
    if (kind === 0x03 && len !== 58) return { ok: false, rule: 3, reason: 'onion hint length' }
    if (kind === 0x04 && len !== 33) return { ok: false, rule: 3, reason: 'ephemeral hint length' }
    const start = off + 3
    off = start + len
    if (off > end) return { ok: false, rule: 3, reason: 'hint runs past the signature' }
    hints.push({ kind, value: bytes.subarray(start, off) })
  }
  if (off !== end) return { ok: false, rule: 3, reason: 'hints do not end at the signature' }
  const nodeId = bytes.subarray(5, 37)
  if (!ed25519.verify(bytes.subarray(end), concatBytes(DOMAIN, bytes.subarray(0, end)), nodeId)) return { ok: false, rule: 4, reason: 'signature' }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const issuedAt = Number(dv.getBigUint64(37)), expiresAt = Number(dv.getBigUint64(45)), serial = Number(dv.getBigUint64(53))
  if (issuedAt > now + 300) return { ok: false, rule: 5, reason: 'issued in the future' }
  if (expiresAt <= now) return { ok: false, rule: 6, reason: 'expired' }
  if (expiresAt <= issuedAt || expiresAt - issuedAt > LINK_CARD_MAX_AGE) return { ok: false, rule: 7, reason: 'expiry window' }
  if (highestSerial !== undefined && serial <= highestSerial) return { ok: false, rule: 8, reason: 'stale serial' }
  const relays = hints.filter((h) => h.kind === 0x01).map((h) => new TextDecoder().decode(h.value))
  const onions = hints.filter((h) => h.kind === 0x03).map((h) => `${new TextDecoder().decode(h.value.subarray(0, 56))}.onion:${(h.value[56]! << 8) | h.value[57]!}`)
  return { ok: true, card: { nodeId: bytesToHex(nodeId), issuedAt, expiresAt, serial, hints, relays, onions } }
}

/** Build an FSL-CARD-1 for a node. Used by boxes and by tests; a client only reads. */
export function buildLinkCard(o: { nodeSecret: Uint8Array; issuedAt: number; expiresAt: number; serial: number; relays?: string[]; onions?: { host: string; port: number }[]; ephemeral?: Uint8Array }): Uint8Array {
  const hints: Uint8Array[] = []
  for (const r of o.relays ?? []) { const v = utf8ToBytes(r); hints.push(concatBytes(new Uint8Array([0x01, v.length >> 8, v.length & 0xff]), v)) }
  for (const on of o.onions ?? []) { const v = concatBytes(utf8ToBytes(on.host), new Uint8Array([on.port >> 8, on.port & 0xff])); hints.push(concatBytes(new Uint8Array([0x03, 0, 58]), v)) }
  if (o.ephemeral) { if (o.ephemeral.length !== 33) throw new Error('ephemeral hint is a 33-byte compressed key'); hints.push(concatBytes(new Uint8Array([0x04, 0, 33]), o.ephemeral)) }
  const head = new Uint8Array(62)
  head.set(utf8ToBytes('FSL1'), 0); head[4] = 1
  head.set(ed25519.getPublicKey(o.nodeSecret), 5)
  const dv = new DataView(head.buffer)
  dv.setBigUint64(37, BigInt(o.issuedAt)); dv.setBigUint64(45, BigInt(o.expiresAt)); dv.setBigUint64(53, BigInt(o.serial))
  head[61] = hints.length
  const body = concatBytes(head, ...hints)
  return concatBytes(body, ed25519.sign(concatBytes(DOMAIN, body), o.nodeSecret))
}
