import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { schnorr } from '@noble/curves/secp256k1.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { buildCard, buildCardWith, readCard, encodeCard, cardLink, refreshBox, buildLinkCard, verifyLinkCard, handshakeBytes, cardContent, eventId, CARD_KIND, type Card, type CardEvent } from '../src/index.js'

const v = JSON.parse(readFileSync(new URL('../vectors/contact-card.json', import.meta.url), 'utf8'))

describe('known-answer vectors from the draft', () => {
  for (const c of v.cases) {
    it(c.name, () => {
      const r = readCard(c.encoded, v.now)
      expect(r.ok).toBe(c.expect.ok)
      if (!r.ok) expect(r.step).toBe(c.expect.step)
      else if (c.expect.stripped) for (const k of c.expect.stripped) expect(k in r.card).toBe(false)
    })
  }
  for (const c of v.refresh.cases) {
    it(`refresh ${c.name}`, () => {
      expect(refreshBox(c.pinnedNodeId ?? v.refresh.pinnedNodeId, new Uint8Array(Buffer.from(c.card, 'base64url')), v.refresh.later, c.highestSerial).ok).toBe(c.expect.ok)
    })
  }
})

describe('build and read', () => {
  const identity = randomBytes(32)
  const rzSecret = randomBytes(32)
  const eph = randomBytes(32)
  const node = randomBytes(32)
  const NOW = 1_800_000_000
  const link = buildLinkCard({ nodeSecret: node, issuedAt: NOW - 60, expiresAt: NOW + 6 * 24 * 3600, serial: 3, relays: ['wss://relay.example'], onions: [{ host: 'b'.repeat(56), port: 443 }] })
  const box = { p: bytesToHex(schnorr.getPublicKey(randomBytes(32))), claim: 'c1'.repeat(32), card: Buffer.from(link).toString('base64url'), carriers: ['tor'] }
  const card = buildCard({ identityPrivateKey: identity, rz: bytesToHex(schnorr.getPublicKey(rzSecret)), ephemeralPrivateKey: eph, name: 'Ada', relays: ['wss://relay.example'], boxes: [box], bond: { pubkey: bytesToHex(schnorr.getPublicKey(identity)), displayName: 'Ada', nonce: bytesToHex(randomBytes(16)) }, now: () => NOW })

  it('round-trips as a link and yields the endorsed box', () => {
    const r = readCard(cardLink('https://example.invalid/join', card), NOW)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.card.p).toBe(bytesToHex(schnorr.getPublicKey(identity)))
    expect(r.boxes.length).toBe(1)
    expect(r.boxes[0]!.link.nodeId).toBe(bytesToHex(ed25519.getPublicKey(node)))
    expect(r.boxes[0]!.link.onions).toEqual([`${'b'.repeat(56)}.onion:443`])
    expect(r.boxes[0]!.link.relays).toEqual(['wss://relay.example'])
  })
  it('a tampered field fails the signature, a foreign key fails too', () => {
    const t: CardEvent = { ...card.event, content: cardContent({ ...card, name: 'Eve' }) }
    expect(readCard(encodeCard(t), NOW)).toMatchObject({ ok: false, step: 4 })
    const stranger = randomBytes(32)
    const forged: CardEvent = { ...card.event, sig: bytesToHex(schnorr.sign(hexToBytes(card.id), stranger)) }
    expect(readCard(encodeCard(forged), NOW)).toMatchObject({ ok: false, step: 4 })
    const moved: CardEvent = { ...card.event, created_at: card.issued + 1 }
    expect(readCard(encodeCard(moved), NOW)).toMatchObject({ ok: false, step: 4 })
  })
  it('a signer that only signs events makes the same card', async () => {
    const signer = async (unsigned: { kind: number; pubkey: string; created_at: number; tags: string[][]; content: string }) => {
      const id = eventId(unsigned)
      return { ...unsigned, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), identity)) }
    }
    const viaSigner = await buildCardWith(bytesToHex(schnorr.getPublicKey(identity)), signer, { rz: bytesToHex(schnorr.getPublicKey(rzSecret)), ephemeralPrivateKey: eph, name: 'Ada', relays: ['wss://relay.example'], boxes: [box], now: () => NOW })
    expect(viaSigner.event.kind).toBe(CARD_KIND)
    expect(viaSigner.p).toBe(card.p)
    expect(readCard(cardLink('https://example.invalid/join', viaSigner), NOW).ok).toBe(true)
    // A signer that alters what it was asked to sign is refused.
    const liar = async (unsigned: { kind: number; pubkey: string; created_at: number; tags: string[][]; content: string }) => signer({ ...unsigned, tags: [...unsigned.tags, ['relay', 'wss://evil.example']] })
    await expect(buildCardWith(card.p, liar, { rz: card.rz, ephemeralPrivateKey: eph, now: () => NOW })).rejects.toThrow(/changed the event/)
  })
  it('refreshes only under the pinned node id and rejects a stale serial', () => {
    const pinned = bytesToHex(ed25519.getPublicKey(node))
    const later = NOW + 10 * 24 * 3600
    const fresh = buildLinkCard({ nodeSecret: node, issuedAt: later - 60, expiresAt: later + 3600, serial: 4, relays: ['wss://relay.example'] })
    expect(refreshBox(pinned, fresh, later, 3).ok).toBe(true)
    expect(refreshBox(pinned, fresh, later, 4)).toMatchObject({ ok: false, reason: 'stale serial' })
    const other = buildLinkCard({ nodeSecret: randomBytes(32), issuedAt: later - 60, expiresAt: later + 3600, serial: 1 })
    expect(refreshBox(pinned, other, later).ok).toBe(false)
  })
  it('bond bytes are canonical whatever the key order', () => {
    const a = handshakeBytes({ pubkey: 'a'.repeat(64), nonce: 'b'.repeat(32), displayName: 'x' })
    const b = handshakeBytes({ displayName: 'x', nonce: 'b'.repeat(32), pubkey: 'a'.repeat(64) } as any)
    expect(bytesToHex(a)).toBe(bytesToHex(b))
    expect(new TextDecoder().decode(a)).toBe('{"v":1,"pubkey":"' + 'a'.repeat(64) + '","displayName":"x","nonce":"' + 'b'.repeat(32) + '"}')
  })
  it('refuses to build a card that cannot be read', () => {
    expect(() => buildCard({ identityPrivateKey: identity, rz: 'zz', ephemeralPrivateKey: eph, now: () => NOW })).toThrow()
    expect(() => buildCard({ identityPrivateKey: identity, rz: bytesToHex(schnorr.getPublicKey(rzSecret)), ephemeralPrivateKey: eph, ttlSeconds: 31 * 24 * 3600, now: () => NOW })).toThrow(/30 days/)
  })
  it('verifies the link card rules in order', () => {
    const bad = new Uint8Array(link); bad[10] ^= 1
    expect(verifyLinkCard(bad, NOW)).toMatchObject({ ok: false, rule: 4 })
    expect(verifyLinkCard(link, NOW + 8 * 24 * 3600)).toMatchObject({ ok: false, rule: 6 })
    expect(verifyLinkCard(link.subarray(0, 100), NOW)).toMatchObject({ ok: false, rule: 1 })
  })
})
