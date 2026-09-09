import { schnorr } from '@noble/curves/secp256k1.js'
import { base64urlnopad } from '@scure/base'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { verifyLinkCard, isRelayUrl, type LinkCard } from './link-card.js'

/** The reserved addressable kind a card rides in. Never published to a relay. */
export const CARD_KIND = 30641
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

/**
 * The card as it travels: a signed Nostr event of `CARD_KIND` whose
 * `pubkey` is `p`, `created_at` is `issued`, `expiration` tag is `expires`
 * and `content` is the card. The signature is the one every signer makes.
 */
export interface CardEvent {
  kind: number
  pubkey: string
  created_at: number
  tags: string[][]
  content: string
  id: string
  sig: string
}

/** The card as read: the named fields, the event's id and signature, and the event itself, for carrying on. */
export interface Card extends UnsignedCard {
  id: string
  sig: string
  event: CardEvent
}

/** What a signer signs: the event without its id and signature. */
export interface UnsignedCardEvent {
  kind: number
  pubkey: string
  created_at: number
  tags: string[][]
  content: string
}

/** The NIP-01 id: sha256 over the serialised array of the six fields. */
export function eventId(ev: UnsignedCardEvent): string {
  return sha256hex(utf8ToBytes(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])))
}

/** §1: the content of a card event, from the fields the draft names, in a fixed order. */
export function cardContent(c: Omit<UnsignedCard, 'p' | 'issued' | 'expires'>): string {
  const o: Record<string, unknown> = { v: 1, rz: c.rz }
  if (c.name !== undefined) o.name = c.name
  o.relays = c.relays
  o.boxes = c.boxes
  o.eph = c.eph
  if (c.attest !== undefined) o.attest = c.attest
  if (c.bond !== undefined) o.bond = c.bond
  return JSON.stringify(o)
}

/** The unsigned event for a card, ready for a signer. */
export function cardEvent(c: UnsignedCard): UnsignedCardEvent {
  return { kind: CARD_KIND, pubkey: c.p, created_at: c.issued, tags: [['d', 'card'], ['expiration', String(c.expires)]], content: cardContent(c) }
}

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/, HEX32 = /^[0-9a-f]{32}$/
const B64URL = /^[A-Za-z0-9_-]+$/
const CARRIER = /^[A-Za-z0-9._-]{1,32}$/
/** What no text field may carry: control, surrogate, unassigned, private-use, line and paragraph separators. */
const UNPRINTABLE = /[\p{Cc}\p{Cs}\p{Cn}\p{Co}\p{Zl}\p{Zp}]/u
/** Invisible and direction-changing format characters that spoof a name; the format characters emoji need are handled apart. */
const INVISIBLE = /[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\u061C\u180E]/u
const VISIBLE = /[\p{L}\p{N}\p{S}\p{P}]/u
const MARK_RUN = /\p{M}{5}/u
const PICTOGRAPHIC = /\p{Extended_Pictographic}/u
// base64url without padding, as the draft specifies; @scure/base is the
// same family as the curves and hashes and runs in a browser.
const b64url = {
  encode: (b: Uint8Array) => base64urlnopad.encode(b),
  decode: (s: string) => base64urlnopad.decode(s.replace(/=+$/, '')),
}
const sha256hex = (b: Uint8Array) => bytesToHex(sha256(b))
const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/**
 * A name, display name or persona label a person will see: 1 to 100 code
 * points, at least one visible one, no control, surrogate, unassigned or
 * private-use character, no separator other than an ordinary space and none
 * of those at the ends, no invisible or direction-changing format character,
 * no run of five combining marks. The format characters emoji sequences use
 * (the zero-width joiner and the tag characters) are allowed only beside a
 * pictographic character, so a family or a flag reads and a hidden joiner
 * does not.
 */
export function isGoodName(s: unknown): s is string {
  if (typeof s !== 'string') return false
  const cps = [...s]
  if (cps.length === 0 || cps.length > MAX_NAME) return false
  if (UNPRINTABLE.test(s) || INVISIBLE.test(s) || MARK_RUN.test(s) || !VISIBLE.test(s)) return false
  if (s.startsWith(' ') || s.endsWith(' ')) return false
  for (let i = 0; i < cps.length; i++) {
    const c = cps[i]!
    const code = c.codePointAt(0)!
    if (/\p{Zs}/u.test(c) && c !== ' ') return false
    if (/\p{Cf}/u.test(c)) {
      const near = (cps[i - 1] ?? '') + (cps[i + 1] ?? '')
      if (code === 0x200d && PICTOGRAPHIC.test(near)) continue
      if (code >= 0xe0020 && code <= 0xe007f && PICTOGRAPHIC.test(cps.slice(Math.max(0, i - 8), i).join(''))) continue
      return false
    }
  }
  return true
}

const goodText = isGoodName

/**
 * A bond handshake with only the fields the draft names, each checked, in
 * canonical key order. Throws with a `handshake:` message on anything else.
 */
export function cleanBond(p: unknown): BondHandshake {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error('handshake: not an object')
  const h = p as Record<string, unknown>
  if (h.v !== undefined && h.v !== 1) throw new Error('handshake: v must be 1')
  const pubkey = typeof h.pubkey === 'string' ? h.pubkey.toLowerCase() : ''
  const nonce = typeof h.nonce === 'string' ? h.nonce.toLowerCase() : ''
  if (!HEX64.test(pubkey)) throw new Error('handshake: pubkey must be 64 hex chars')
  if (!HEX32.test(nonce)) throw new Error('handshake: nonce must be 32 hex chars')
  if (h.displayName !== undefined && !goodText(h.displayName)) throw new Error('handshake: displayName')
  const out: BondHandshake = { v: 1, pubkey, nonce }
  if (h.displayName !== undefined) out.displayName = h.displayName as string
  if (h.personas !== undefined) {
    if (!Array.isArray(h.personas) || h.personas.length > MAX_PERSONAS) throw new Error('handshake: personas')
    out.personas = h.personas.map((x) => {
      const pk = x && typeof x === 'object' && typeof x.pubkey === 'string' ? x.pubkey.toLowerCase() : ''
      if (!HEX64.test(pk)) throw new Error('handshake: persona pubkey')
      if (x.label !== undefined && !goodText(x.label)) throw new Error('handshake: persona label')
      return x.label !== undefined ? { pubkey: pk, label: x.label } : { pubkey: pk }
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

export interface BuildOptions {
  /** The identity's secret key, for a client that holds one. Otherwise use `buildCardWith` and a signer. */
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

/** A signer as NIP-07 and NIP-46 expose one: given the unsigned event, returns it signed. */
export type SignEvent = (unsigned: UnsignedCardEvent) => Promise<CardEvent> | CardEvent

function unsignedFor(p: string, o: Omit<BuildOptions, 'identityPrivateKey'>): { unsigned: UnsignedCard; now: number } {
  const now = (o.now ?? (() => Math.floor(Date.now() / 1000)))()
  const ttl = o.ttlSeconds ?? MAX_AGE_SECONDS
  if (ttl <= 0 || ttl > MAX_AGE_SECONDS) throw new Error('ttl must be within 30 days')
  const unsigned: UnsignedCard = {
    v: 1,
    p,
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
  return { unsigned, now }
}

function finish(event: CardEvent, now: number): Card {
  const encoded = encodeCard(event)
  if (encoded.length > MAX_CARD_BYTES) throw new Error('card exceeds 16 KiB; drop a box')
  const r = readCard(encoded, now)
  if (!r.ok) throw new Error(`built a card that does not read: step ${r.step} ${r.reason}`)
  return r.card
}

/** Build and sign a card with a secret key held here. Throws when it would not fit or would not verify. */
export function buildCard(o: BuildOptions): Card {
  const p = bytesToHex(schnorr.getPublicKey(o.identityPrivateKey))
  const { unsigned, now } = unsignedFor(p, o)
  const ev = cardEvent(unsigned)
  const id = eventId(ev)
  const event: CardEvent = { ...ev, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), o.identityPrivateKey)) }
  return finish(event, now)
}

/**
 * Build a card through a signer that holds the key: a NIP-07 extension, a
 * NIP-46 bunker, anything that signs an event. `p` is the signer's pubkey.
 * The signed event is checked to be the one asked for before it is read.
 */
export async function buildCardWith(p: string, signEvent: SignEvent, o: Omit<BuildOptions, 'identityPrivateKey'>): Promise<Card> {
  const pub = String(p).toLowerCase()
  if (!HEX64.test(pub)) throw new Error('p must be a 32-byte x-only public key as hex')
  const { unsigned, now } = unsignedFor(pub, o)
  const ev = cardEvent(unsigned)
  const signed = await signEvent(ev)
  if (!signed || typeof signed !== 'object') throw new Error('signer returned nothing')
  for (const k of ['kind', 'pubkey', 'created_at', 'tags', 'content'] as const) {
    if (JSON.stringify((signed as unknown as Record<string, unknown>)[k]) !== JSON.stringify(ev[k])) throw new Error(`signer changed the event's ${k}`)
  }
  return finish({ kind: signed.kind, pubkey: signed.pubkey, created_at: signed.created_at, tags: signed.tags, content: signed.content, id: signed.id, sig: signed.sig }, now)
}

/** The bytes a card travels as: the event's JSON, base64url without padding. */
export function encodeCard(card: Card | CardEvent): string {
  const event = 'event' in card ? card.event : card
  return b64url.encode(utf8ToBytes(JSON.stringify({ kind: event.kind, pubkey: event.pubkey, created_at: event.created_at, tags: event.tags, content: event.content, id: event.id, sig: event.sig })))
}

/** A link a person can send: the card rides after `#`, so no server sees it. */
export function cardLink(base: string, card: Card | CardEvent): string {
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
  if (!Number.isFinite(now)) return { ok: false, step: 3, reason: 'clock' }
  let ev: any
  // Strict UTF-8: a byte sequence that is not UTF-8 is not a card, not a card with U+FFFD in it.
  try { ev = JSON.parse(utf8Strict.decode(b64url.decode(body))) } catch { return { ok: false, step: 1, reason: 'decode' } }
  if (!ev || typeof ev !== 'object' || Array.isArray(ev) || ev.kind !== CARD_KIND || typeof ev.content !== 'string') return { ok: false, step: 1, reason: 'version' }
  let c: any
  try { c = JSON.parse(ev.content) } catch { return { ok: false, step: 1, reason: 'decode' } }
  if (!c || typeof c !== 'object' || Array.isArray(c) || c.v !== 1) return { ok: false, step: 1, reason: 'version' }
  // Step 2: the event's own shape, then the card's fields.
  if (typeof ev.pubkey !== 'string') return { ok: false, step: 2, reason: 'p' }
  const p = ev.pubkey.toLowerCase()
  if (!HEX64.test(p)) return { ok: false, step: 2, reason: 'p' }
  if (typeof ev.id !== 'string') return { ok: false, step: 2, reason: 'id' }
  const id = ev.id.toLowerCase()
  if (!HEX64.test(id)) return { ok: false, step: 2, reason: 'id' }
  if (typeof ev.sig !== 'string') return { ok: false, step: 2, reason: 'sig' }
  const sig = ev.sig.toLowerCase()
  if (!HEX128.test(sig)) return { ok: false, step: 2, reason: 'sig' }
  // Exactly a `d` of `card` and one `expiration`, nothing else: a tag is inside the signature, and a third could carry what a card may not.
  if (!Array.isArray(ev.tags) || ev.tags.length !== 2 || !ev.tags.every((t: unknown) => Array.isArray(t) && t.length === 2 && t.every((x) => typeof x === 'string'))) return { ok: false, step: 2, reason: 'tags' }
  const tags = ev.tags as string[][]
  const dTag = tags.find((t) => t[0] === 'd'), expTag = tags.find((t) => t[0] === 'expiration')
  if (!dTag || !expTag || dTag[1] !== 'card') return { ok: false, step: 2, reason: 'tags' }
  const hex: Record<'rz' | 'eph', string> = { rz: '', eph: '' }
  for (const f of ['rz', 'eph'] as const) {
    if (typeof c[f] !== 'string') return { ok: false, step: 2, reason: f }
    hex[f] = c[f].toLowerCase()
    if (!HEX64.test(hex[f])) return { ok: false, step: 2, reason: f }
  }
  if (c.name !== undefined && !goodText(c.name)) return { ok: false, step: 2, reason: 'name' }
  if (!Array.isArray(c.relays) || c.relays.length > MAX_RELAYS || c.relays.some((r: unknown) => !isRelayUrl(r as string))) return { ok: false, step: 2, reason: 'relays' }
  if (!Array.isArray(c.boxes) || c.boxes.length > MAX_BOXES) return { ok: false, step: 2, reason: 'boxes' }
  const boxesClean: Box[] = []
  for (const b of c.boxes) {
    if (!b || typeof b !== 'object' || Array.isArray(b)) return { ok: false, step: 2, reason: 'box' }
    const bp = typeof b.p === 'string' ? b.p.toLowerCase() : ''
    const claim = typeof b.claim === 'string' ? b.claim.toLowerCase() : ''
    if (!HEX64.test(bp)) return { ok: false, step: 2, reason: 'box p' }
    if (!HEX64.test(claim)) return { ok: false, step: 2, reason: 'box claim' }
    if (typeof b.card !== 'string' || !B64URL.test(b.card)) return { ok: false, step: 2, reason: 'box card' }
    if (b.carriers !== undefined && (!Array.isArray(b.carriers) || b.carriers.length === 0 || b.carriers.length > 8 || b.carriers.some((x: unknown) => typeof x !== 'string' || !CARRIER.test(x)))) return { ok: false, step: 2, reason: 'box carriers' }
    boxesClean.push({ p: bp, claim, card: b.card, ...(b.carriers !== undefined ? { carriers: [...b.carriers] as string[] } : {}) })
  }
  if (c.attest !== undefined && (typeof c.attest !== 'string' || c.attest.length === 0 || c.attest.includes(':') || UNPRINTABLE.test(c.attest) || INVISIBLE.test(c.attest) || /\p{Z}/u.test(c.attest) || c.attest.length > 512)) return { ok: false, step: 2, reason: 'attest' }
  let bond: BondHandshake | undefined
  if (c.bond !== undefined) {
    try { bond = cleanBond(c.bond) } catch { return { ok: false, step: 2, reason: 'bond' } }
  }
  // Step 3: issued is the event's created_at, expires the expiration tag's value.
  const issued = ev.created_at
  if (!Number.isSafeInteger(issued) || !/^(0|[1-9][0-9]{0,15})$/.test(expTag[1]!)) return { ok: false, step: 3, reason: 'times' }
  const expires = Number(expTag[1])
  if (!Number.isSafeInteger(expires)) return { ok: false, step: 3, reason: 'times' }
  if (expires <= now) return { ok: false, step: 3, reason: 'expired' }
  if (expires <= issued || expires - issued > MAX_AGE_SECONDS) return { ok: false, step: 3, reason: 'expiry window' }
  if (issued > now + 300) return { ok: false, step: 3, reason: 'issued in the future' }
  // Step 4: the id over the six fields as carried, and the signature under p.
  // The id and signature are returned lower-cased; the pubkey is inside the hashed serialisation, so a pubkey not already lower-case fails the id check.
  const event: CardEvent = { kind: ev.kind, pubkey: ev.pubkey, created_at: issued, tags, content: ev.content, id, sig }
  if (eventId(event) !== id || !schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(p))) return { ok: false, step: 4, reason: 'signature' }
  const card: Card = {
    v: 1,
    p,
    rz: hex.rz,
    ...(c.name !== undefined ? { name: c.name as string } : {}),
    issued,
    expires,
    relays: [...c.relays] as string[],
    boxes: boxesClean,
    eph: hex.eph,
    ...(c.attest !== undefined ? { attest: c.attest as string } : {}),
    ...(bond ? { bond } : {}),
    id,
    sig,
    event,
  }
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

/**
 * §3 step 6: accept a fresh Link card from a box only under the node id the
 * person endorsed. Pass the highest serial previously accepted for that node
 * id, persisted by the caller; without it any unexpired old card of the same
 * node replays, which is rule 8's job to stop and this function cannot do
 * alone.
 */
export function refreshBox(pinnedNodeId: string | Uint8Array, freshCard: Uint8Array, now: number, highestSerial?: number): { ok: true; link: LinkCard } | { ok: false; reason: string } {
  const pin = pinnedNodeId instanceof Uint8Array ? bytesToHex(pinnedNodeId) : typeof pinnedNodeId === 'string' ? pinnedNodeId.toLowerCase() : ''
  if (!HEX64.test(pin)) return { ok: false, reason: 'pinned node id is not 32 bytes of hex' }
  const v = verifyLinkCard(freshCard, now, highestSerial)
  if (!v.ok) return { ok: false, reason: v.reason }
  if (v.card.nodeId !== pin) return { ok: false, reason: 'node id is not the endorsed one' }
  return { ok: true, link: v.card }
}
