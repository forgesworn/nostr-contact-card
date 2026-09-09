import { ed25519 } from '@noble/curves/ed25519.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

/** forgesworn-link SPEC.md §2: the domain prefix a card signature covers. */
const DOMAIN = concatBytes(utf8ToBytes('forgesworn-link/card/v1'), new Uint8Array([0]))
export const LINK_CARD_MAX = 4096
export const LINK_CARD_MIN = 126
export const LINK_CARD_MAX_AGE = 604800

const ONION_HOST = /^[a-z2-7]{56}$/
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER)
const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const Point = ed25519.Point
const L = Point.CURVE().n
/** Control, format, separator, surrogate, unassigned and private-use characters have no place in a URL. */
const URL_UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Z}\p{Cs}\p{Cn}\p{Co}]/u

/**
 * Is this a relay URL a client may dial? `wss://`, parses as a URL with a
 * DNS name or IP literal as host, no credentials, no fragment, no comma (the contact card digest joins
 * relays on commas), no unprintable character. Word for word what
 * forgesworn-link SPEC §2.2 asks of a relay hint, so a verifier using a
 * URL parser in another language reaches the same verdict.
 */
export function isRelayUrl(s: string): boolean {
  if (typeof s !== 'string' || s.length === 0 || s.length > 255 || s.includes(',') || URL_UNPRINTABLE.test(s) || !s.startsWith('wss://')) return false
  let u: URL
  try { u = new URL(s) } catch { return false }
  // A host is a DNS name or an IP literal, never punctuation the URL parser happens to tolerate.
  const host = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(u.hostname) || /^\[[0-9a-f:.]+\]$/.test(u.hostname)
  return u.protocol === 'wss:' && u.username === '' && u.password === '' && u.hash === '' && host
}

function leNum(b: Uint8Array): bigint {
  let n = 0n
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!)
  return n
}

/**
 * Ed25519 as libsodium and ed25519-dalek's `verify_strict` check it: A and R
 * decode canonically, neither is of small order, S < L, and the equation is
 * cofactorless, `[S]B = R + [k]A`. noble's `verify` multiplies both sides by
 * the cofactor, which accepts an A or R carrying a torsion component that a
 * strict verifier refuses; two implementations would then disagree on the
 * same bytes, which SPEC §2.3 forbids.
 */
export function verifyStrict(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  if (sig.length !== 64 || pk.length !== 32) return false
  let A, R
  try { A = Point.fromBytes(pk, false); R = Point.fromBytes(sig.subarray(0, 32), false) } catch { return false }
  if (A.isSmallOrder() || R.isSmallOrder()) return false
  const S = leNum(sig.subarray(32))
  if (S >= L) return false
  const k = leNum(sha512(concatBytes(sig.subarray(0, 32), pk, msg))) % L
  try {
    return Point.BASE.multiply(S).equals(R.add(A.multiplyUnsafe(k)))
  } catch { return false }
}

export interface LinkHint { kind: number; value: Uint8Array }
export interface LinkCard {
  nodeId: string
  issuedAt: number
  expiresAt: number
  serial: number
  /** Every hint, raw. Kinds 0x01 and 0x03 are checked and also given as `relays` and `onions`; 0x04 has its prefix checked; 0x02 and unknown kinds are exactly the bytes the box wrote. */
  hints: LinkHint[]
  /** Relay hints (kind 0x01) as URLs, each checked by `isRelayUrl`. */
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
 * caller passes when it has one. `now` must be a finite number of seconds
 * and `highestSerial` a safe integer or absent; anything else fails closed
 * rather than switching a rule off.
 */
export function verifyLinkCard(bytes: Uint8Array, now: number, highestSerial?: number): LinkVerdict {
  if (!Number.isFinite(now)) return { ok: false, rule: 5, reason: 'clock' }
  if (highestSerial !== undefined && !Number.isSafeInteger(highestSerial)) return { ok: false, rule: 8, reason: 'highest serial is not an integer' }
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
    // caller as relays and onions is checked here, never raw bytes the box chose.
    if (kind === 0x01) {
      let s: string
      try { s = utf8Strict.decode(value) } catch { return { ok: false, rule: 3, reason: 'relay hint utf-8' } }
      if (value[0] === 0xef && value[1] === 0xbb && value[2] === 0xbf) return { ok: false, rule: 3, reason: 'relay hint utf-8' }
      if (!isRelayUrl(s)) return { ok: false, rule: 3, reason: 'relay hint url' }
      relays.push(s)
    }
    if (kind === 0x03) {
      const host = String.fromCharCode(...value.subarray(0, 56))
      const port = (value[56]! << 8) | value[57]!
      if (!ONION_HOST.test(host) || port === 0) return { ok: false, rule: 3, reason: 'onion hint' }
      onions.push(`${host}.onion:${port}`)
    }
    if (kind === 0x04 && value[0] !== 0x02 && value[0] !== 0x03) return { ok: false, rule: 3, reason: 'ephemeral hint prefix' }
  }
  if (off !== end) return { ok: false, rule: 3, reason: 'hints do not end at the signature' }
  // The three u64 fields are read before the signature so a serial that Number
  // cannot hold is reported under rule 3, where SPEC §2.3 puts it.
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const issuedBig = dv.getBigUint64(37), expiresBig = dv.getBigUint64(45), serialBig = dv.getBigUint64(53)
  if (serialBig > MAX_SAFE) return { ok: false, rule: 3, reason: 'serial too large' }
  const nodeId = bytes.subarray(5, 37)
  if (!verifyStrict(bytes.subarray(end), concatBytes(DOMAIN, bytes.subarray(0, end)), nodeId)) return { ok: false, rule: 4, reason: 'signature' }
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
