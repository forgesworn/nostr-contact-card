import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { readCard, verifyLinkCard, refreshBox, buildLinkCard, handshakeBytes } from '../src/index.js'

// A tiny seeded generator so a failure reproduces from its seed.
function rng(seed: number) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0x100000000 } }
const v = JSON.parse(readFileSync(new URL('../vectors/contact-card.json', import.meta.url), 'utf8'))
const good = v.cases.find((c: any) => c.name === 'passes')
const NOW = v.now
const N = 1500

describe('fuzz: readCard', () => {
  it('random bytes never read and never throw', () => {
    const r = rng(1)
    for (let i = 0; i < N; i++) {
      const len = Math.floor(r() * 300)
      const bytes = Buffer.from(Array.from({ length: len }, () => Math.floor(r() * 256)))
      const s = r() < 0.5 ? bytes.toString('base64url') : bytes.toString('latin1')
      let out
      expect(() => { out = readCard(s, NOW) }).not.toThrow()
      expect((out as any).ok).toBe(false)
    }
  })
  it('a flipped byte is accepted only when it changes nothing: hex case is the one such flip', () => {
    const r = rng(2)
    const raw = Buffer.from(good.encoded, 'base64url')
    const canonical = JSON.stringify((readCard(good.encoded, NOW) as any).card)
    let accepted = 0
    for (let i = 0; i < N; i++) {
      const b = Buffer.from(raw)
      const at = Math.floor(r() * b.length)
      b[at] ^= 1 << Math.floor(r() * 8)
      let out: any
      expect(() => { out = readCard(b.toString('base64url'), NOW) }).not.toThrow()
      if (out.ok) {
        accepted++
        // Whatever was accepted reads as exactly the same card after normalisation.
        expect(JSON.stringify(out.card)).toBe(canonical)
        // And the only difference on the wire is letter case inside a hex field.
        expect(b.toString('utf8').toLowerCase()).toBe(raw.toString('utf8').toLowerCase())
      }
    }
    expect(accepted).toBeLessThan(N / 4)
  })
  it('truncations and oversize are refused without throwing', () => {
    for (let cut = 0; cut < good.encoded.length; cut += 37) {
      let out
      expect(() => { out = readCard(good.encoded.slice(0, cut), NOW) }).not.toThrow()
      expect((out as any).ok).toBe(false)
    }
    expect(readCard(good.encoded + 'A'.repeat(20000), NOW).ok).toBe(false)
  })
  it('structural mutations of the JSON are refused', () => {
    const r = rng(3)
    const obj = JSON.parse(Buffer.from(good.encoded, 'base64url').toString('utf8'))
    const keys = Object.keys(obj)
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
    for (let i = 0; i < 400; i++) {
      const m = JSON.parse(JSON.stringify(obj))
      const k = keys[Math.floor(r() * keys.length)]!
      const op = Math.floor(r() * 5)
      if (op === 0) delete m[k]
      else if (op === 1) m[k] = null
      else if (op === 2) m[k] = 12345
      else if (op === 3) m[k] = Array.isArray(m[k]) ? {} : []
      else m[k] = typeof m[k] === 'string' ? m[k] + 'x' : 'x'
      let out
      expect(() => { out = readCard(enc(m), NOW) }).not.toThrow()
      expect((out as any).ok).toBe(false)
    }
  })
})

describe('fuzz: link card and handshake', () => {
  it('random bytes and flipped bits never verify', () => {
    const r = rng(4)
    const node = Buffer.from(Array.from({ length: 32 }, () => Math.floor(r() * 256)))
    const card = buildLinkCard({ nodeSecret: node, issuedAt: NOW - 60, expiresAt: NOW + 3600, serial: 1, relays: ['wss://relay.example'] })
    expect(verifyLinkCard(card, NOW).ok).toBe(true)
    for (let i = 0; i < N; i++) {
      const b = new Uint8Array(card)
      b[Math.floor(r() * b.length)] ^= 1 << Math.floor(r() * 8)
      let out
      expect(() => { out = verifyLinkCard(b, NOW) }).not.toThrow()
      expect((out as any).ok).toBe(false)
      const junk = new Uint8Array(Math.floor(r() * 5000)).map(() => Math.floor(r() * 256))
      expect(() => { out = verifyLinkCard(junk, NOW) }).not.toThrow()
      expect((out as any).ok).toBe(false)
      expect(() => refreshBox('0'.repeat(64), junk, NOW)).not.toThrow()
    }
  })
  it('handshakeBytes refuses bad keys without throwing anything but its own error', () => {
    for (const p of [{ pubkey: 'x', nonce: 'y' }, { pubkey: 'a'.repeat(64), nonce: 'z' }, { pubkey: 'A'.repeat(64), nonce: 'b'.repeat(32) }] as any[]) {
      expect(() => handshakeBytes(p)).toThrow(/handshake:/)
    }
  })
})
