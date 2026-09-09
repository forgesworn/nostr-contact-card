// One directed test per finding of the 2026-09-09 independent review.
import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, hexToBytes, randomBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { buildCard, readCard, encodeCard, cardLink, refreshBox, buildLinkCard, verifyLinkCard, handshakeBytes, cleanBond, cardContent, eventId, CARD_KIND, MAX_NAME, MAX_CARD_BYTES, type Card, type CardEvent } from '../src/index.js'

const NOW = 1_800_000_000
const RTL_OVERRIDE = '‮'
const identity = randomBytes(32)
const p = bytesToHex(schnorr.getPublicKey(identity))
const rz = bytesToHex(schnorr.getPublicKey(randomBytes(32)))
const node = randomBytes(32)
const LINK_DOMAIN = concatBytes(utf8ToBytes('forgesworn-link/card/v1'), new Uint8Array([0]))
const link = buildLinkCard({ nodeSecret: node, issuedAt: NOW - 60, expiresAt: NOW + 6 * 24 * 3600, serial: 3, relays: ['wss://relay.example'], onions: [{ host: 'b'.repeat(56), port: 443 }] })
const box = { p: bytesToHex(schnorr.getPublicKey(randomBytes(32))), claim: 'c1'.repeat(32), card: Buffer.from(link).toString('base64url'), carriers: ['tor'] }
const good = buildCard({ identityPrivateKey: identity, rz, ephemeralPrivateKey: randomBytes(32), name: 'Ada', relays: ['wss://relay.example'], boxes: [box], bond: { pubkey: p, displayName: 'Ada', nonce: bytesToHex(randomBytes(16)) }, now: () => NOW })
const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')

/** The card's content fields as the reader returned them. */
const contentOf = (c: Card) => ({ rz: c.rz, ...(c.name !== undefined ? { name: c.name } : {}), relays: c.relays, boxes: c.boxes, eph: c.eph, ...(c.attest !== undefined ? { attest: c.attest } : {}), ...(c.bond !== undefined ? { bond: c.bond } : {}) })
/** Sign an arbitrary content string as a card event under `identity`: what a card with extras inside its signed content looks like. */
const signed = (content: string, ev: Partial<CardEvent> = {}): CardEvent => {
  const base = { kind: CARD_KIND, pubkey: p, created_at: good.issued, tags: [['expiration', String(good.expires)]], content, ...ev }
  const id = eventId(base)
  return { ...base, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), identity)) }
}
/** The wire bytes of the good card with its content re-serialised from changed fields and the signature kept, or its event fields changed: what a tamperer sends. */
const wire = (over: Record<string, unknown> = {}, ev: Partial<CardEvent> = {}) => enc({ ...good.event, content: Object.keys(over).length ? cardContent({ ...contentOf(good), ...over } as never) : good.event.content, ...ev })

describe('P1: only the named fields come back', () => {
  it('extra keys at every level are dropped, not returned under a verified signature', () => {
    // On the event, outside the signature; inside the content, signed and still not returned.
    const inside = JSON.parse(good.event.content)
    inside.boxes[0].extra = 'x'
    inside.bond.v = 99
    inside.bond.evil = true
    expect(readCard(enc({ ...signed(JSON.stringify(inside)), nip05: 'ada@evil.example' }), NOW).ok).toBe(false)   // bond.v 99 is refused outright
    inside.bond.v = 1
    const r = readCard(enc({ ...signed(JSON.stringify(inside)), nip05: 'ada@evil.example', lud16: 'ada@evil.example' }), NOW)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    const c = r.card as unknown as Record<string, unknown>
    expect('nip05' in c).toBe(false)
    expect('lud16' in c).toBe(false)
    expect('extra' in (r.card.boxes[0] as unknown as Record<string, unknown>)).toBe(false)
    expect('evil' in (r.card.bond as unknown as Record<string, unknown>)).toBe(false)
    expect(Object.keys(r.card).sort()).toEqual(['bond', 'boxes', 'eph', 'event', 'expires', 'id', 'issued', 'name', 'p', 'relays', 'rz', 'sig', 'v'])
    expect(Object.keys(r.card.event).sort()).toEqual(['content', 'created_at', 'id', 'kind', 'pubkey', 'sig', 'tags'])
  })
  it('__proto__ on the wire cannot reach a consumer that copies the card', () => {
    const raw = '{"__proto__":{"isAdmin":true},' + JSON.stringify(good.event).slice(1)
    const r = readCard(Buffer.from(raw).toString('base64url'), NOW)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    const target: Record<string, unknown> = {}
    Object.assign(target, r.card)
    expect(Object.getPrototypeOf(target)).toBe(Object.prototype)
    expect((target as { isAdmin?: boolean }).isAdmin).toBeUndefined()
  })
})

describe('P2: link card verification is strict', () => {
  function forged(nodeId: Uint8Array): Uint8Array {
    const head = new Uint8Array(62)
    head.set(utf8ToBytes('FSL1'), 0); head[4] = 1
    head.set(nodeId, 5)
    const dv = new DataView(head.buffer)
    dv.setBigUint64(37, BigInt(NOW - 60)); dv.setBigUint64(45, BigInt(NOW + 3600)); dv.setBigUint64(53, 1n)
    // R = the identity point, S = 0: verifies for every message under a small-order key in ZIP-215 mode.
    const sig = new Uint8Array(64); sig[0] = 1
    return concatBytes(head, sig)
  }
  it('a small-order node id with a universal signature is refused', () => {
    const identityPoint = new Uint8Array(32); identityPoint[0] = 1
    for (const id of [identityPoint, new Uint8Array(32)]) {
      const v = verifyLinkCard(forged(id), NOW)
      expect(v.ok).toBe(false)
      if (!v.ok) expect(v.rule).toBe(4)
      expect(refreshBox(bytesToHex(id), forged(id), NOW).ok).toBe(false)
    }
    expect(verifyLinkCard(link, NOW).ok).toBe(true)
  })
  it('hint content is checked: relay urls and onion hosts, never raw bytes', () => {
    const bad = (relays?: string[], onions?: { host: string; port: number }[]) => verifyLinkCard(buildLinkCard({ nodeSecret: node, issuedAt: NOW - 60, expiresAt: NOW + 3600, serial: 1, relays, onions }), NOW)
    expect(bad(['javascript:alert(1)'])).toMatchObject({ ok: false, rule: 3 })
    expect(bad(['ws://10.0.0.1:4444'])).toMatchObject({ ok: false, rule: 3 })
    expect(bad(['wss://a.example, wss://b.example'])).toMatchObject({ ok: false, rule: 3 })
    expect(bad(['wss://ok.example']).ok).toBe(true)
    expect(bad(undefined, [{ host: 'B'.repeat(56), port: 443 }])).toMatchObject({ ok: false, rule: 3 })
    expect(bad(undefined, [{ host: 'b'.repeat(56), port: 0 }])).toMatchObject({ ok: false, rule: 3 })
    expect(bad(undefined, [{ host: 'b'.repeat(56), port: 443 }]).ok).toBe(true)
    // Invalid UTF-8 in a relay hint: built by hand around the signer.
    const raw = new Uint8Array([0xff, 0xfe, 0x77, 0x73, 0x73])
    const head = new Uint8Array(62); head.set(utf8ToBytes('FSL1'), 0); head[4] = 1; head.set(ed25519.getPublicKey(node), 5)
    const dv = new DataView(head.buffer); dv.setBigUint64(37, BigInt(NOW - 60)); dv.setBigUint64(45, BigInt(NOW + 3600)); dv.setBigUint64(53, 1n); head[61] = 1
    const body = concatBytes(head, new Uint8Array([0x01, 0, raw.length]), raw)
    const card = concatBytes(body, ed25519.sign(concatBytes(LINK_DOMAIN, body), node))
    expect(verifyLinkCard(card, NOW)).toMatchObject({ ok: false, rule: 3, reason: 'relay hint utf-8' })
  })
  it('a serial above 2^53 is refused rather than rounded', () => {
    const card = buildLinkCard({ nodeSecret: node, issuedAt: NOW - 60, expiresAt: NOW + 3600, serial: 1, relays: ['wss://relay.example'] })
    const body = new Uint8Array(card.subarray(0, card.length - 64))
    new DataView(body.buffer).setBigUint64(53, 2n ** 64n - 1n)
    const resigned = concatBytes(body, ed25519.sign(concatBytes(LINK_DOMAIN, body), node))
    expect(verifyLinkCard(resigned, NOW)).toMatchObject({ ok: false, rule: 3, reason: 'serial too large' })
  })
})

describe('P2: bond handshake and names are validated', () => {
  it('handshakeBytes refuses the wrong shapes', () => {
    const nonce = 'a'.repeat(32)
    expect(() => handshakeBytes({ pubkey: p, nonce, displayName: { html: '<img>' } } as never)).toThrow(/displayName/)
    expect(() => handshakeBytes({ pubkey: p, nonce, personas: [{ pubkey: 'not-hex' }] } as never)).toThrow(/persona/)
    expect(() => handshakeBytes({ pubkey: p, nonce, personas: [{ pubkey: p, label: [1, 2] }] } as never)).toThrow(/persona label/)
    expect(() => handshakeBytes({ pubkey: p, nonce, personas: {} } as never)).toThrow(/personas/)
    expect(() => handshakeBytes({ v: 2, pubkey: p, nonce } as never)).toThrow(/v must be 1/)
    expect(() => handshakeBytes({ pubkey: p, nonce, displayName: 'x'.repeat(MAX_NAME + 1) })).toThrow(/displayName/)
    expect(() => handshakeBytes({ pubkey: p, nonce, displayName: 'Ada' + RTL_OVERRIDE })).toThrow(/displayName/)
    expect(cleanBond({ pubkey: p, nonce, personas: [{ pubkey: p, label: 'work' }] })).toEqual({ v: 1, pubkey: p, nonce, personas: [{ pubkey: p, label: 'work' }] })
  })
  it('a name that is too long or carries a format or control character fails step 2', () => {
    for (const name of ['x'.repeat(MAX_NAME + 1), 'Ada' + RTL_OVERRIDE, 'Ada ', 'Ada ']) {
      expect(readCard(wire({ name }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'name' })
    }
    expect(readCard(wire({ name: 'x'.repeat(MAX_NAME) }), NOW)).toMatchObject({ ok: false, step: 4 })   // right shape, wrong signature
  })
})

describe('P2: fields keep their bounds, and the size cap is the card', () => {
  it('box card outside base64url, an empty carrier, and a separator carrier fail step 2', () => {
    expect(readCard(wire({ boxes: [{ ...box, card: box.card + ':x' }] }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'box card' })
    expect(readCard(wire({ boxes: [{ ...box, card: box.card + ',' }] }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'box card' })
    expect(readCard(wire({ boxes: [{ ...box, carriers: [''] }] }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'box carriers' })
    expect(readCard(wire({ boxes: [{ ...box, carriers: ['tor+i2p'] }] }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'box carriers' })
    expect(readCard(wire({ relays: ['wss://a.example/x:1'] }), NOW)).toMatchObject({ ok: false, step: 4 })   // allowed shape, signature decides
    expect(readCard(wire({ attest: 'a:b' }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'attest' })
    // A third tag, even a harmless one, is refused before the signature is looked at.
    expect(readCard(wire({}, { tags: [...good.event.tags, ['t', 'x']] }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'tags' })
  })
  it('a card just inside the cap reads on any base url', () => {
    const big = buildCard({ identityPrivateKey: identity, rz, ephemeralPrivateKey: randomBytes(32), name: 'x'.repeat(MAX_NAME), relays: Array.from({ length: 8 }, (_, i) => `wss://relay${i}.example/${'a'.repeat(200)}`), boxes: [box, box, box, box], now: () => NOW })
    const e = encodeCard(big)
    expect(e.length).toBeLessThanOrEqual(MAX_CARD_BYTES)
    expect(e.length).toBeGreaterThan(3000)
    expect(readCard(cardLink('https://example.invalid/' + 'p'.repeat(MAX_CARD_BYTES), big), NOW).ok).toBe(true)
    expect(readCard('#', NOW)).toMatchObject({ ok: false, step: 1 })
  })
})

describe('P2: the checks the vectors do not cover', () => {
  it('issued in the future, too many relays, a non-wss relay, a bond pubkey other than p', () => {
    expect(readCard(wire(), NOW - 3600)).toMatchObject({ ok: false, step: 3, reason: 'issued in the future' })
    expect(readCard(wire({ relays: Array(9).fill('wss://r.example') }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'relays' })
    expect(readCard(wire({ relays: ['https://r.example'] }), NOW)).toMatchObject({ ok: false, step: 2, reason: 'relays' })
    // The draft allows a bond pubkey other than p (a persona); it is signed, so it is the person's choice.
    const other = buildCard({ identityPrivateKey: identity, rz, ephemeralPrivateKey: randomBytes(32), bond: { pubkey: rz, nonce: 'a'.repeat(32) }, now: () => NOW })
    expect(readCard(encodeCard(other), NOW).ok).toBe(true)
  })
  it('link rules 2, 3 at the signature boundary, 5 and 7', () => {
    const magic = new Uint8Array(link); magic[0] ^= 1
    expect(verifyLinkCard(magic, NOW)).toMatchObject({ ok: false, rule: 2 })
    const overrun = new Uint8Array(link); overrun[61] = 3   // says three hints, the bytes hold two
    expect(verifyLinkCard(overrun, NOW)).toMatchObject({ ok: false, rule: 3 })
    const future = buildLinkCard({ nodeSecret: node, issuedAt: NOW + 3600, expiresAt: NOW + 7200, serial: 1 })
    expect(verifyLinkCard(future, NOW)).toMatchObject({ ok: false, rule: 5 })
    const window = buildLinkCard({ nodeSecret: node, issuedAt: NOW - 60, expiresAt: NOW + 8 * 24 * 3600, serial: 1 })
    expect(verifyLinkCard(window, NOW)).toMatchObject({ ok: false, rule: 7 })
  })
})
