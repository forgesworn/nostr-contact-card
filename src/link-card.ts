import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

/** forgesworn-link SPEC.md §2: the domain prefix a card signature covers. */
const DOMAIN = concatBytes(utf8ToBytes('forgesworn-link/card/v1'), new Uint8Array([0]))
export const LINK_CARD_MAX = 4096
export const LINK_CARD_MIN = 126
export const LINK_CARD_MAX_AGE = 604800

const RELAY_URL = /^wss:\/\/[^\s,]+$/u
const ONION_HOST = /^[a-z2-7]{56}$/
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER)
const utf8Strict = new TextDecoder('utf-8', { fatal: true })

export interface LinkHint { kind: number; value: Uint8Array }
export interface LinkCard {
  nodeId: string
  issuedAt: number
  expiresAt: number
  serial: number
  hints: LinkHint[]
  /** Relay hints (kind 0x01) as URLs, each a well-formed `wss://` URL. */
  relays: string[]
  /** Onion hints (kind 0x03) as `host.onion:port`, host 56 base32 characters, port non-zero. */
  onions: string[]
}

export type LinkVerdict = { ok: true; card: LinkCard } | { ok: false; rule: number; reason: string }

/**
 * Verify an FSL-CARD-1 by SPEC §2.3 rules 1 to 8. Rule 9, the expected node
 * id, is applied by `refreshBox`, which is where a client has one; `readCard`
 * accepts whatever node id the person endorsed and returns it for pinning.
 * Rule 8, the serial, needs the highest serial previously accepted, which the
 * caller passes when it has one.
 *
 * The signature check is strict RFC 8032, not ZIP-215: a non-canonical
 * encoding is refused, and a node id of small order is refused before the
 * signature is looked at, because under such a key a fixed signature
 * verifies for every message.
 */
export function verifyLinkCard(bytes: Uint8Array, now: number, highestSerial?: number): LinkVerdict {
  if (!(bytes instanceof Uint8Array) || bytes.length < LINK_CARD_MIN || bytes.length > LINK_CARD_MAX) return { ok: false, rule: 1, reason: 'length' }
  if (String.fromCharCode(...bytes.subarray(0, 4)) !== 'FSL1' || bytes[4] !== 1) return { ok: false, rule: 2, reason: 'magic or version' }
  const count = bytes[61]!
  if (count > 16) return { ok: false, rule: 3, reason: 'hint count' }
  const end = bytes.length - 64
  let off = 62
  const hints: LinkHint[] = []
  const relays: string[] = []
  const onions: string[] = []
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
    const value = bytes.slice(start, off)
    hints.push({ kind, value })
    // A hint's value must be what its kind says it is. What comes back to the
    // caller is checked here, never raw bytes the box chose.
    if (kind === 0x01) {
      let s: string
      try { s = utf8Strict.decode(value) } catch { return { ok: false, rule: 3, reason: 'relay hint utf-8' } }
      if (!RELAY_URL.test(s)) return { ok: false, rule: 3, reason: 'relay hint url' }
      relays.push(s)
    }
    if (kind === 0x03) {
      const host = String.fromCharCode(...value.subarray(0, 56))
      const port = (value[56]! << 8) | value[57]!
      if (!ONION_HOST.test(host) || port === 0) return { ok: false, rule: 3, reason: 'onion hint' }
      onions.push(`${host}.onion:${port}`)
    }
  }
  if (off !== end) return { ok: false, rule: 3, reason: 'hints do not end at the signature' }
  const nodeId = bytes.subarray(5, 37)
  let point
  try { point = ed25519.Point.fromBytes(nodeId, false) } catch { return { ok: false, rule: 4, reason: 'node id' } }
  if (point.isSmallOrder()) return { ok: false, rule: 4, reason: 'node id has small order' }
  let sigOk = false
  try { sigOk = ed25519.verify(bytes.subarray(end), concatBytes(DOMAIN, bytes.subarray(0, end)), nodeId, { zip215: false }) } catch { sigOk = false }
  if (!sigOk) return { ok: false, rule: 4, reason: 'signature' }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const issuedBig = dv.getBigUint64(37), expiresBig = dv.getBigUint64(45), serialBig = dv.getBigUint64(53)
  // 64-bit fields that Number cannot hold exactly: the times fail rules 5 and 7
  // whatever they are; the serial must stay exact or two cards could compare equal.
  if (serialBig > MAX_SAFE) return { ok: false, rule: 3, reason: 'serial too large' }
  const issuedAt = issuedBig > MAX_SAFE ? Number.MAX_SAFE_INTEGER : Number(issuedBig)
  const expiresAt = expiresBig > MAX_SAFE ? Number.MAX_SAFE_INTEGER : Number(expiresBig)
  const serial = Number(serialBig)
  if (issuedAt > now + 300) return { ok: false, rule: 5, reason: 'issued in the future' }
  if (expiresAt <= now) return { ok: false, rule: 6, reason: 'expired' }
  if (expiresAt <= issuedAt || expiresAt - issuedAt > LINK_CARD_MAX_AGE) return { ok: false, rule: 7, reason: 'expiry window' }
  if (highestSerial !== undefined && serial <= highestSerial) return { ok: false, rule: 8, reason: 'stale serial' }
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
