import { schnorr } from '@noble/curves/secp256k1.js'
import { base64urlnopad } from '@scure/base'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { verifyLinkCard, type LinkCard } from './link-card.js'

export const CARD_DOMAIN = 'nostr-contact-card:v1'
export const MAX_CARD_BYTES = 16 * 1024
export const MAX_AGE_SECONDS = 30 * 24 * 3600
export const MAX_RELAYS = 8
export const MAX_BOXES = 4
/** Longest name, display name or persona label, in code points. */
export const MAX_NAME = 100
export const MAX_PERSONAS = 16

export interface BondHandshake {
  v?: 1
  pubkey: string
  displayName?: string
  nonce: string
  personas?: { pubkey: string; label?: string }[]
}

export interface Box {
  /** The box's own key, x-only hex. */
  p: string
  /** The box's binding event id, where the box publishes one. */
  claim: string
  /** FSL-CARD-1, base64url without padding, carried opaquely. */
  card: string
  carriers?: string[]
}

export interface UnsignedCard {
  v: 1
  p: string
  rz: string
  name?: string
  issued: number
  expires: number
  relays: string[]
  boxes: Box[]
  eph: string
  attest?: string
  bond?: BondHandshake
}
export interface Card extends UnsignedCard { sig: string }

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/, HEX32 = /^[0-9a-f]{32}$/
const B64URL = /^[A-Za-z0-9_-]+$/
const CARRIER = /^[A-Za-z0-9._-]{1,32}$/
/** Control, format, and line or paragraph separator characters: nothing a name needs, everything a spoof does. */
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u
// base64url without padding, as the draft specifies; @scure/base is the
// same family as the curves and hashes and runs in a browser.
const b64url = {
  encode: (b: Uint8Array) => base64urlnopad.encode(b),
  decode: (s: string) => base64urlnopad.decode(s.replace(/=+$/, '')),
}
const sha256hex = (b: Uint8Array) => bytesToHex(sha256(b))

function goodText(s: unknown): s is string {
  return typeof s === 'string' && [...s].length <= MAX_NAME && !UNPRINTABLE.test(s)
}

/**
 * A bond handshake with only the fields the draft names, each checked, in
 * canonical key order. Throws with a `handshake:` message on anything else.
 */
export function cleanBond(p: unknown): BondHandshake {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error('handshake: not an object')
  const h = p as Record<string, unknown>
  if (h.v !== undefined && h.v !== 1) throw new Error('handshake: v must be 1')
  if (typeof h.pubkey !== 'string' || !HEX64.test(h.pubkey)) throw new Error('handshake: pubkey must be 64 hex chars')
  if (typeof h.nonce !== 'string' || !HEX32.test(h.nonce)) throw new Error('handshake: nonce must be 32 hex chars')
  if (h.displayName !== undefined && !goodText(h.displayName)) throw new Error('handshake: displayName')
  const out: BondHandshake = { v: 1, pubkey: h.pubkey, nonce: h.nonce }
  if (h.displayName !== undefined) out.displayName = h.displayName as string
  if (h.personas !== undefined) {
    if (!Array.isArray(h.personas) || h.personas.length > MAX_PERSONAS) throw new Error('handshake: personas')
    out.personas = h.personas.map((x) => {
      if (!x || typeof x !== 'object' || typeof x.pubkey !== 'string' || !HEX64.test(x.pubkey)) throw new Error('handshake: persona pubkey')
      if (x.label !== undefined && !goodText(x.label)) throw new Error('handshake: persona label')
      return x.label !== undefined ? { pubkey: x.pubkey, label: x.label } : { pubkey: x.pubkey }
    })
  }
  return out
}

/** The canonical bytes of a bond handshake: fixed key order, no whitespace, absent keys omitted. */
export function handshakeBytes(p: BondHandshake): Uint8Array {
  const c = cleanBond(p)
  const o: Record<string, unknown> = { v: 1, pubkey: c.pubkey }
  if (c.displayName !== undefined) o.displayName = c.displayName
  o.nonce = c.nonce
  if (c.personas !== undefined) o.personas = c.personas
  return utf8ToBytes(JSON.stringify(o))
}

/**
 * §2 of the draft: the digest the card's signature covers. Fields are
 * colon-joined; every field that could carry a separator is constrained by
 * `readCard` step 2 (relays no comma, box cards base64url, carriers a
 * short token alphabet, attest no colon) so no two well-formed cards share
 * a digest.
 */
export function cardDigest(c: UnsignedCard): Uint8Array {
  const box = (b: Box) => `${b.p}/${b.claim}/${b.card}/${(b.carriers ?? []).join('+')}`
  const s = [CARD_DOMAIN, c.p, c.rz, String(c.issued), String(c.expires), c.eph,
    c.relays.join(','), c.boxes.map(box).join(','), c.attest ?? '',
    c.bond ? sha256hex(handshakeBytes(c.bond)) : '', sha256hex(utf8ToBytes(c.name ?? ''))].join(':')
  return sha256(utf8ToBytes(s))
}

export interface BuildOptions {
  identityPrivateKey: Uint8Array
  /** The rendezvous public key, a child of the root, x-only hex. */
  rz: string
  /** A fresh ephemeral secret for this card; its public half goes on the card. */
  ephemeralPrivateKey: Uint8Array
  name?: string
  relays?: string[]
  boxes?: Box[]
  attest?: string
  bond?: Omit<BondHandshake, 'v'>
  /** Card lifetime in seconds, at most 30 days. */
  ttlSeconds?: number
  now?: () => number
}

/** Build and sign a card. Throws when it would not fit or would not verify. */
export function buildCard(o: BuildOptions): Card {
  const now = (o.now ?? (() => Math.floor(Date.now() / 1000)))()
  const ttl = o.ttlSeconds ?? MAX_AGE_SECONDS
  if (ttl <= 0 || ttl > MAX_AGE_SECONDS) throw new Error('ttl must be within 30 days')
  const unsigned: UnsignedCard = {
    v: 1,
    p: bytesToHex(schnorr.getPublicKey(o.identityPrivateKey)),
    rz: o.rz,
    ...(o.name !== undefined ? { name: o.name } : {}),
    issued: now,
    expires: now + ttl,
    relays: o.relays ?? [],
    boxes: o.boxes ?? [],
    eph: bytesToHex(schnorr.getPublicKey(o.ephemeralPrivateKey)),
    ...(o.attest !== undefined ? { attest: o.attest } : {}),
    ...(o.bond !== undefined ? { bond: cleanBond({ v: 1, ...o.bond }) } : {}),
  }
  const card: Card = { ...unsigned, sig: bytesToHex(schnorr.sign(cardDigest(unsigned), o.identityPrivateKey)) }
  const encoded = encodeCard(card)
  if (encoded.length > MAX_CARD_BYTES) throw new Error('card exceeds 16 KiB; drop a box')
  const r = readCard(encoded, now)
  if (!r.ok) throw new Error(`built a card that does not read: step ${r.step} ${r.reason}`)
  return card
}

export function encodeCard(card: Card): string {
  return b64url.encode(utf8ToBytes(JSON.stringify(card)))
}

/** A link a person can send: the card rides after `#`, so no server sees it. */
export function cardLink(base: string, card: Card): string {
  return `${base.replace(/#.*$/, '')}#${encodeCard(card)}`
}

export interface ReadOk {
  ok: true
  /** Only the fields the draft names, each checked; nothing else from the wire survives. */
  card: Card
  /** Each box with its verified Link card; the node id is the one `p` endorsed. */
  boxes: { box: Box; link: LinkCard }[]
}
export type ReadResult = ReadOk | { ok: false; step: 1 | 2 | 3 | 4 | 5; reason: string }

/**
 * §3 steps 1 to 5. The result names the step that failed, for the words a
 * client shows. The card returned is rebuilt from the fields the draft
 * names: an extra key on the wire, `__proto__` included, never reaches the
 * caller under a verified signature.
 */
export function readCard(encoded: string, now: number): ReadResult {
  if (typeof encoded !== 'string') return { ok: false, step: 1, reason: 'size' }
  const body = encoded.slice(encoded.lastIndexOf('#') + 1)
  if (body.length === 0 || body.length > MAX_CARD_BYTES) return { ok: false, step: 1, reason: 'size' }
  let c: any
  try { c = JSON.parse(new TextDecoder().decode(b64url.decode(body))) } catch { return { ok: false, step: 1, reason: 'decode' } }
  if (!c || typeof c !== 'object' || Array.isArray(c) || c.v !== 1) return { ok: false, step: 1, reason: 'version' }
  const hex: Record<'p' | 'rz' | 'eph', string> = { p: '', rz: '', eph: '' }
  for (const f of ['p', 'rz', 'eph'] as const) {
    if (typeof c[f] !== 'string') return { ok: false, step: 2, reason: f }
    hex[f] = c[f].toLowerCase()
    if (!HEX64.test(hex[f])) return { ok: false, step: 2, reason: f }
  }
  if (typeof c.sig !== 'string') return { ok: false, step: 2, reason: 'sig' }
  const sig = c.sig.toLowerCase()
  if (!HEX128.test(sig)) return { ok: false, step: 2, reason: 'sig' }
  if (c.name !== undefined && !goodText(c.name)) return { ok: false, step: 2, reason: 'name' }
  if (!Array.isArray(c.relays) || c.relays.length > MAX_RELAYS || c.relays.some((r: unknown) => typeof r !== 'string' || !/^wss:\/\/[^\s,]+$/u.test(r))) return { ok: false, step: 2, reason: 'relays' }
  if (!Array.isArray(c.boxes) || c.boxes.length > MAX_BOXES) return { ok: false, step: 2, reason: 'boxes' }
  const boxesClean: Box[] = []
  for (const b of c.boxes) {
    if (!b || typeof b !== 'object' || Array.isArray(b)) return { ok: false, step: 2, reason: 'box' }
    const p = typeof b.p === 'string' ? b.p.toLowerCase() : ''
    const claim = typeof b.claim === 'string' ? b.claim.toLowerCase() : ''
    if (!HEX64.test(p)) return { ok: false, step: 2, reason: 'box p' }
    if (!HEX64.test(claim)) return { ok: false, step: 2, reason: 'box claim' }
    if (typeof b.card !== 'string' || !B64URL.test(b.card)) return { ok: false, step: 2, reason: 'box card' }
    if (b.carriers !== undefined && (!Array.isArray(b.carriers) || b.carriers.length > 8 || b.carriers.some((x: unknown) => typeof x !== 'string' || !CARRIER.test(x)))) return { ok: false, step: 2, reason: 'box carriers' }
    boxesClean.push({ p, claim, card: b.card, ...(b.carriers !== undefined ? { carriers: [...b.carriers] as string[] } : {}) })
  }
  if (c.attest !== undefined && (typeof c.attest !== 'string' || c.attest.includes(':') || UNPRINTABLE.test(c.attest) || c.attest.length > 512)) return { ok: false, step: 2, reason: 'attest' }
  let bond: BondHandshake | undefined
  if (c.bond !== undefined) {
    try { bond = cleanBond(c.bond) } catch { return { ok: false, step: 2, reason: 'bond' } }
  }
  if (!Number.isSafeInteger(c.issued) || !Number.isSafeInteger(c.expires)) return { ok: false, step: 3, reason: 'times' }
  if (c.expires <= now) return { ok: false, step: 3, reason: 'expired' }
  if (c.expires - c.issued > MAX_AGE_SECONDS) return { ok: false, step: 3, reason: 'too long' }
  if (c.issued > now + 300) return { ok: false, step: 3, reason: 'issued in the future' }
  const unsigned: UnsignedCard = {
    v: 1,
    p: hex.p,
    rz: hex.rz,
    ...(c.name !== undefined ? { name: c.name as string } : {}),
    issued: c.issued,
    expires: c.expires,
    relays: [...c.relays] as string[],
    boxes: boxesClean,
    eph: hex.eph,
    ...(c.attest !== undefined ? { attest: c.attest as string } : {}),
    ...(bond ? { bond } : {}),
  }
  if (!schnorr.verify(hexToBytes(sig), cardDigest(unsigned), hexToBytes(unsigned.p))) return { ok: false, step: 4, reason: 'signature' }
  const card: Card = { ...unsigned, sig }
  const boxes: ReadOk['boxes'] = []
  for (const b of card.boxes) {
    let bytes: Uint8Array
    try { bytes = b64url.decode(b.card) } catch { return { ok: false, step: 5, reason: 'link: decode' } }
    const v = verifyLinkCard(bytes, now)
    if (!v.ok) return { ok: false, step: 5, reason: `link: ${v.reason}` }
    boxes.push({ box: b, link: v.card })
  }
  return { ok: true, card, boxes }
}

/** §3 step 6: accept a fresh Link card from a box only under the node id the person endorsed. */
export function refreshBox(pinnedNodeId: string, freshCard: Uint8Array, now: number, highestSerial?: number): { ok: true; link: LinkCard } | { ok: false; reason: string } {
  const v = verifyLinkCard(freshCard, now, highestSerial)
  if (!v.ok) return { ok: false, reason: v.reason }
  if (v.card.nodeId !== pinnedNodeId) return { ok: false, reason: 'node id is not the endorsed one' }
  return { ok: true, link: v.card }
}
