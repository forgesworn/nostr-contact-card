import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { verifyLinkCard, type LinkCard } from './link-card.js'

export const CARD_DOMAIN = 'nostr-contact-card:v1'
export const MAX_CARD_BYTES = 16 * 1024
export const MAX_AGE_SECONDS = 30 * 24 * 3600
export const MAX_RELAYS = 8
export const MAX_BOXES = 4

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
  /** FSL-CARD-1, base64url, carried opaquely. */
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
const b64url = {
  encode: (b: Uint8Array) => Buffer.from(b).toString('base64url'),
  decode: (s: string) => new Uint8Array(Buffer.from(s, 'base64url')),
}
const sha256hex = (b: Uint8Array) => bytesToHex(sha256(b))

/** The canonical bytes of a bond handshake: fixed key order, no whitespace, absent keys omitted. */
export function handshakeBytes(p: BondHandshake): Uint8Array {
  if (!HEX64.test(p.pubkey)) throw new Error('handshake: pubkey must be 64 hex chars')
  if (!HEX32.test(p.nonce)) throw new Error('handshake: nonce must be 32 hex chars')
  const o: Record<string, unknown> = { v: 1, pubkey: p.pubkey }
  if (p.displayName !== undefined) o.displayName = p.displayName
  o.nonce = p.nonce
  if (p.personas !== undefined) o.personas = p.personas.map((x) => (x.label !== undefined ? { pubkey: x.pubkey, label: x.label } : { pubkey: x.pubkey }))
  return utf8ToBytes(JSON.stringify(o))
}

/** §2 of the draft: the digest the card's signature covers. */
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
    ...(o.bond !== undefined ? { bond: { v: 1, ...o.bond } } : {}),
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
  card: Card
  /** Each box with its verified Link card; the node id is the one `p` endorsed. */
  boxes: { box: Box; link: LinkCard }[]
}
export type ReadResult = ReadOk | { ok: false; step: 1 | 2 | 3 | 4 | 5; reason: string }

/** §3 steps 1 to 5. The result names the step that failed, for the words a client shows. */
export function readCard(encoded: string, now: number): ReadResult {
  if (typeof encoded !== 'string' || encoded.length > MAX_CARD_BYTES) return { ok: false, step: 1, reason: 'size' }
  let c: any
  try { c = JSON.parse(new TextDecoder().decode(b64url.decode(encoded.replace(/^.*#/, '')))) } catch { return { ok: false, step: 1, reason: 'decode' } }
  if (!c || typeof c !== 'object' || c.v !== 1) return { ok: false, step: 1, reason: 'version' }
  for (const f of ['p', 'rz', 'eph'] as const) {
    if (typeof c[f] !== 'string') return { ok: false, step: 2, reason: f }
    c[f] = c[f].toLowerCase()
    if (!HEX64.test(c[f])) return { ok: false, step: 2, reason: f }
  }
  if (typeof c.sig !== 'string') return { ok: false, step: 2, reason: 'sig' }
  c.sig = c.sig.toLowerCase()
  if (!HEX128.test(c.sig)) return { ok: false, step: 2, reason: 'sig' }
  if (c.name !== undefined && typeof c.name !== 'string') return { ok: false, step: 2, reason: 'name' }
  if (!Array.isArray(c.relays) || c.relays.length > MAX_RELAYS || c.relays.some((r: unknown) => typeof r !== 'string' || !r.startsWith('wss://') || r.includes(','))) return { ok: false, step: 2, reason: 'relays' }
  if (!Array.isArray(c.boxes) || c.boxes.length > MAX_BOXES) return { ok: false, step: 2, reason: 'boxes' }
  for (const b of c.boxes) {
    if (!b || typeof b !== 'object') return { ok: false, step: 2, reason: 'box' }
    for (const f of ['p', 'claim'] as const) {
      if (typeof b[f] !== 'string') return { ok: false, step: 2, reason: `box ${f}` }
      b[f] = b[f].toLowerCase()
      if (!HEX64.test(b[f])) return { ok: false, step: 2, reason: `box ${f}` }
    }
    if (typeof b.card !== 'string' || b.card.includes('/')) return { ok: false, step: 2, reason: 'box card' }
    if (b.carriers !== undefined && (!Array.isArray(b.carriers) || b.carriers.some((x: unknown) => typeof x !== 'string' || /[\/+,]/.test(x)))) return { ok: false, step: 2, reason: 'box carriers' }
  }
  if (c.attest !== undefined && (typeof c.attest !== 'string' || c.attest.includes(':'))) return { ok: false, step: 2, reason: 'attest' }
  if (c.bond !== undefined) {
    try { handshakeBytes(c.bond) } catch { return { ok: false, step: 2, reason: 'bond' } }
  }
  if (!Number.isSafeInteger(c.issued) || !Number.isSafeInteger(c.expires)) return { ok: false, step: 3, reason: 'times' }
  if (c.expires <= now) return { ok: false, step: 3, reason: 'expired' }
  if (c.expires - c.issued > MAX_AGE_SECONDS) return { ok: false, step: 3, reason: 'too long' }
  if (c.issued > now + 300) return { ok: false, step: 3, reason: 'issued in the future' }
  const { sig, ...unsigned } = c as Card
  if (!schnorr.verify(hexToBytes(sig), cardDigest(unsigned), hexToBytes(c.p))) return { ok: false, step: 4, reason: 'signature' }
  const boxes: ReadOk['boxes'] = []
  for (const b of c.boxes as Box[]) {
    let bytes: Uint8Array
    try { bytes = b64url.decode(b.card) } catch { return { ok: false, step: 5, reason: 'link: decode' } }
    const v = verifyLinkCard(bytes, now)
    if (!v.ok) return { ok: false, step: 5, reason: `link: ${v.reason}` }
    boxes.push({ box: b, link: v.card })
  }
  return { ok: true, card: c as Card, boxes }
}

/** §3 step 6: accept a fresh Link card from a box only under the node id the person endorsed. */
export function refreshBox(pinnedNodeId: string, freshCard: Uint8Array, now: number, highestSerial?: number): { ok: true; link: LinkCard } | { ok: false; reason: string } {
  const v = verifyLinkCard(freshCard, now, highestSerial)
  if (!v.ok) return { ok: false, reason: v.reason }
  if (v.card.nodeId !== pinnedNodeId) return { ok: false, reason: 'node id is not the endorsed one' }
  return { ok: true, link: v.card }
}
