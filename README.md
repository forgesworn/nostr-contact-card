# nostr-contact-card

[![CI](https://github.com/forgesworn/nostr-contact-card/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/nostr-contact-card/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/nostr-contact-card)](https://www.npmjs.com/package/nostr-contact-card)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](./LICENCE)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

**One QR or link that makes a stranger a contact, names their box, and starts a bond.**

A contact card is a signed Nostr event of kind 21641, in the ephemeral
range and never posted to a relay, carried after `#` in a link or as the
whole of a QR code. The kind is ephemeral so that a relay which meets a
card by mistake does not store it: a card carries a rendezvous key, a fresh
ephemeral and a bond nonce, and a leaked one should not sit on a relay for
thirty days. The event's pubkey is the person's key, its created_at is when the
card was issued, its expiration tag is when it lapses, and its content is
the card, so the signature is the one every signer already makes: an
extension, a bunker or a key held locally all make the same card. It holds a person's key and name, their public
relays, their box (a Link address card, carried opaquely, that the person's
signature endorses), a rendezvous key and a fresh ephemeral for deriving
private rendezvous material, an optional attestation pointer, and a bond
handshake so an in-person ceremony can start from the card.

Reading a card needs nothing from the network: five checks, in order (listed
under [How a card is read](#how-a-card-is-read)), and the result names the
step that failed so the client can say why. What comes
back is rebuilt from the fields the draft names, each checked; an extra key
on the wire never reaches the caller under a verified signature. Dialling
the box afterwards is on the person's own word; a later fresh address from
the box is accepted only under the node id they endorsed, which the client
pins from the first read (the Link card inside a contact card lasts seven
days, the card itself thirty, so a client keeps the node id it read).

## Requirements

- ESM only: the package has `"type": "module"` and an `import` export, with
  no CommonJS entry, so use `import`, not `require`.
- Node 22 or later (`engines`), and browsers: the library source uses no
  Node-only API, and its three runtime dependencies, `@noble/curves`,
  `@noble/hashes` and `@scure/base`, run in a browser.
- Every time is Unix seconds, never `Date.now()` milliseconds. `now` is a
  number of seconds everywhere it appears, and a millisecond value makes
  every card read as expired (see [Security notes](#security-notes)).

## Install

```bash
npm install nostr-contact-card
```

The example below runs as written. The two noble imports and `@scure/base`
are this package's own runtime dependencies. Install them directly if your
bundler or package manager does not let you import a transitive dependency.

```ts
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { base64urlnopad } from '@scure/base'
import {
  buildCard, buildCardWith, buildLinkCard, cardLink, eventId, readCard, refreshBox,
  type Box, type UnsignedCardEvent,
} from 'nostr-contact-card'

const now = Math.floor(Date.now() / 1000)   // Unix seconds, not Date.now() milliseconds
const sixDays = 6 * 24 * 3600

// The box's side. A client receives these; they are made here so the example runs.
const nodeSecret = randomBytes(32)          // the box's Ed25519 node key
const linkCardBytes = buildLinkCard({ nodeSecret, issuedAt: now, expiresAt: now + sixDays, serial: 1, relays: ['wss://relay.example.org'] })
const box: Box = {
  p: bytesToHex(schnorr.getPublicKey(randomBytes(32))),   // the box's own x-only key, 64 hex characters
  claim: '00'.repeat(32),                                 // the box's binding event id, 64 hex (a placeholder here)
  card: base64urlnopad.encode(linkCardBytes),             // its Link card, base64url without padding
}

// Your side.
const identityPrivateKey = randomBytes(32)
const pubkey = bytesToHex(schnorr.getPublicKey(identityPrivateKey))
const rz = bytesToHex(schnorr.getPublicKey(randomBytes(32)))   // a stand-in: use your rendezvous key (see nostr-deaddrop)
const ephemeralPrivateKey = randomBytes(32)                    // fresh for each card; only its public half is carried
const relays = ['wss://relay.example.org']
const bond = { pubkey, displayName: 'Ada', nonce: bytesToHex(randomBytes(16)) }   // nonce: 32 hex characters

const card = buildCard({ identityPrivateKey, rz, ephemeralPrivateKey, name: 'Ada', relays, boxes: [box], bond })

// Or through a signer that holds the key. This one stands in for NIP-07
// (window.nostr.signEvent) or NIP-46; any function from unsigned event to signed event will do.
const signEvent = async (unsigned: UnsignedCardEvent) => {
  const id = eventId(unsigned)
  return { ...unsigned, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), identityPrivateKey)) }
}
const viaSigner = await buildCardWith(pubkey, signEvent, { rz, ephemeralPrivateKey, name: 'Ada', relays, boxes: [box] })

const url = cardLink('https://your.app/join', card)   // the card rides after #, which a server never sees

// The reader's side.
const r = readCard(url, now)                          // the whole link, or just the text after '#'
if (!r.ok) throw new Error(`not a card: step ${r.step}, ${r.reason}`)
console.log(r.card.p, r.card.name)

// Pin each box's node id with the highest serial seen for it, and persist both.
const highestSerial = new Map<string, number>()
for (const b of r.boxes) {
  console.log(b.box.p, b.link.nodeId, b.link.relays, b.link.onions)   // dial b.link.relays or b.link.onions
  highestSerial.set(b.link.nodeId, b.link.serial)
}

// Later the box sends a fresh Link card (serial 2). Accept it only under the pinned node id.
const later = now + 3600
const freshBytes = buildLinkCard({ nodeSecret, issuedAt: later, expiresAt: later + sixDays, serial: 2, relays: ['wss://relay.example.org'] })
const nodeId = r.boxes[0]!.link.nodeId
const fresh = refreshBox(nodeId, freshBytes, later, highestSerial.get(nodeId))
if (fresh.ok) highestSerial.set(nodeId, fresh.link.serial)
else console.error(fresh.reason)
```

Always pass the highest serial you have accepted for the node id to
`refreshBox`. The argument is optional in the type, but leaving it out
switches replay protection off: any unexpired old Link card of that node is
accepted. Leave it out only when you have never accepted a Link card for
that node id.

## Terms

- **The draft** is the contact card specification this package implements.
  The source cites its sections (§1 the content of a card, §3 the reading
  steps and the refresh), and `vectors/contact-card.json` is its
  known-answer file. **The profile** is the wider specification the draft
  belongs to; [What remains](#what-remains) quotes its table. This
  repository links no public copy of either.
- **Card**: the signed event described above, as built by `buildCard` and
  returned by `readCard` (type `Card`).
- **Link card**: the signed address card of a box, `FSL-CARD-1` in
  [forgesworn-link's SPEC §2](https://github.com/forgesworn/forgesworn-link/blob/main/SPEC.md):
  magic `FSL1`, a 32-byte Ed25519 node id, issue and expiry times, a
  serial, up to 16 hints and a 64-byte signature, 126 to 4096 bytes in all.
  A Link card lasts at most seven days.
- **Box**: a node the person's contact card names (type `Box`: `p`, the
  box's own x-only key; `claim`, the box's binding event id, 64 hex
  characters; `card`, its Link card as base64url without padding;
  `carriers`, an optional list of 1 to 8 labels of letters, digits, `.`,
  `_` and `-`, up to 32 characters each). The card carries the Link card
  opaquely and the person's signature endorses it. Its node id, the Ed25519
  key inside the Link card, is what a client pins.
- **Hint**: an entry in a Link card telling a client where to reach the
  box. Kind `0x01` is a `wss://` relay URL, checked by `isRelayUrl` and
  returned as `relays`. Kind `0x02` is an 18-byte UDP candidate (a 16-byte
  IPv6 address, IPv4 as `::ffff:a.b.c.d`, then a 2-byte port): the length is
  checked and the bytes come back untouched in `hints`. Kind `0x03` is a
  v3 onion host of 56 base32 characters and a non-zero 2-byte port,
  returned as `onions` (`host.onion:port`). Kind `0x04` is a 33-byte
  ephemeral key hint whose first byte must be `0x02` or `0x03`; it is
  not in the public SPEC's §2.2 table, and this library checks its length
  and prefix byte.
  Unknown kinds are kept in `hints` as written.
- **Bond**: the handshake a card carries so an in-person ceremony can start
  from it (type `BondHandshake`): `pubkey`, 64 hex characters; `nonce`, 32
  hex characters, a bearer secret for the card's life; an optional
  `displayName`; and optional `personas`.
- **displayName**: the name the bond shows, separate from the card's own
  `name`. Both pass `isGoodName`.
- **Persona**: an extra key a bond offers, `{ pubkey, label? }`, up to 16
  of them; the label passes `isGoodName`.
- **attest**: an optional attestation pointer on the card: a string of 1 to
  512 characters with no `:`, no whitespace and no invisible or unprintable
  character. The library checks it and carries it; it does not interpret it.
- **rz and eph**: the card's rendezvous public key and the public half of
  its fresh ephemeral key, both x-only hex. They are inputs to deriving
  private rendezvous material, which
  [nostr-deaddrop](https://github.com/forgesworn/nostr-deaddrop) does.

## API

Everything is a named export of `nostr-contact-card`. All times are Unix
seconds. The full source types are in `dist/index.d.ts` after a build.

### Building and encoding

```ts
buildCard(o: BuildOptions): Card
buildCardWith(p: string, signEvent: SignEvent, o: Omit<BuildOptions, 'identityPrivateKey'>): Promise<Card>
encodeCard(card: Card | CardEvent): string      // the event's JSON, base64url without padding
cardLink(base: string, card: Card | CardEvent): string   // `${base}#${encodeCard(card)}`, any fragment on base replaced

interface BuildOptions {
  identityPrivateKey: Uint8Array        // buildCard only; buildCardWith takes the signer's pubkey instead
  rz: string                            // rendezvous public key, x-only hex
  ephemeralPrivateKey: Uint8Array       // fresh per card; its public half becomes `eph`
  name?: string
  relays?: string[]                     // up to MAX_RELAYS, each passing isRelayUrl; default []
  boxes?: Box[]                         // up to MAX_BOXES; default []
  attest?: string
  bond?: Omit<BondHandshake, 'v'>
  ttlSeconds?: number                   // lifetime, above 0 and at most MAX_AGE_SECONDS (the default)
  now?: () => number                    // a function returning Unix seconds; default is the current time
}
type SignEvent = (unsigned: UnsignedCardEvent) => Promise<CardEvent> | CardEvent
```

`buildCard` and `buildCardWith` return a `Card` after reading it back with
`readCard`, and throw when the lifetime is out of range, the card is over
`MAX_CARD_BYTES`, or a field would not read. `buildCardWith` also throws
when `p` is not 64 hex characters, or the signer returns nothing or changes
the event's kind, pubkey, created_at, tags or content.

### Reading and refreshing

```ts
readCard(encoded: string, now: number): ReadResult
refreshBox(pinnedNodeId: string | Uint8Array, freshCard: Uint8Array, now: number, highestSerial?: number):
  { ok: true; link: LinkCard } | { ok: false; reason: string }

type ReadResult = ReadOk | { ok: false; step: 1 | 2 | 3 | 4 | 5; reason: string }
interface ReadOk {
  ok: true
  card: Card                            // only the fields the draft names, each checked
  boxes: { box: Box; link: LinkCard }[] // each box with its verified Link card, in card order
}
interface Card extends UnsignedCard {   // v: 1, p, rz, name?, issued, expires, relays, boxes, eph, attest?, bond?
  id: string                            // the event id, lower-case hex
  sig: string                           // the event signature, lower-case hex
  event: CardEvent                      // the signed event, to pass on unchanged
}
interface CardEvent { kind: number; pubkey: string; created_at: number; tags: string[][]; content: string; id: string; sig: string }
interface UnsignedCardEvent { kind: number; pubkey: string; created_at: number; tags: string[][]; content: string }
```

`readCard` takes the whole link or just the text after the last `#`.
`ok: false` carries the failing `step` (see [How a card is read](#how-a-card-is-read))
and a `reason` string. On success, the node id to pin for each box is
`boxes[i].link.nodeId`; keep `boxes[i].link.serial` with it.

`refreshBox` is the draft's step 6. It accepts a fresh Link card only when
it verifies (rules 1 to 8 below), is newer than `highestSerial`, and its
node id equals `pinnedNodeId` (rule 9); a byte-array pin is accepted. It
returns the verified `LinkCard`, or a `reason` and no rule number: the
reason of the failing Link card rule, `node id is not the endorsed one`, or
`pinned node id is not 32 bytes of hex`. Persist
the returned `link.serial` per node id and pass it back as `highestSerial`
next time. Without `highestSerial`, rule 8 is off and any unexpired old
Link card of the same node is accepted.

### Link cards

```ts
verifyLinkCard(bytes: Uint8Array, now: number, highestSerial?: number): LinkVerdict
buildLinkCard(o: {
  nodeSecret: Uint8Array                // the node's Ed25519 secret key
  issuedAt: number; expiresAt: number; serial: number
  relays?: string[]                     // kind 0x01 hints
  onions?: { host: string; port: number }[]   // kind 0x03 hints; host is the 56 characters without ".onion"
  ephemeral?: Uint8Array                // kind 0x04 hint, a 33-byte compressed public key
}): Uint8Array                          // for boxes and tests; a client only reads

type LinkVerdict = { ok: true; card: LinkCard } | { ok: false; rule: number; reason: string }
interface LinkCard {
  nodeId: string                        // the Ed25519 node id, 64 hex characters: the key to pin
  issuedAt: number; expiresAt: number
  serial: number
  hints: { kind: number; value: Uint8Array }[]   // every hint, raw
  relays: string[]                      // kind 0x01 hints, each passing isRelayUrl
  onions: string[]                      // kind 0x03 hints as host.onion:port
}
```

`verifyLinkCard` is the one place the failing `rule` is returned. As with
`refreshBox`, pass the highest serial you have accepted for that node id, or
rule 8 is not applied.

### Checks and helpers

```ts
isGoodName(s: unknown): s is string     // the name rules under Security notes
isRelayUrl(s: string): boolean          // the relay URL rules under Security notes
verifyStrict(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean   // strict, cofactorless Ed25519
cleanBond(p: unknown): BondHandshake    // only the named fields, lower-cased and checked; throws Error('handshake: ...')
handshakeBytes(p: BondHandshake): Uint8Array   // canonical bytes: fixed key order, no whitespace; throws as cleanBond does
eventId(ev: UnsignedCardEvent): string  // the NIP-01 id: sha256 of [0, pubkey, created_at, kind, tags, content]
cardContent(c: Omit<UnsignedCard, 'p' | 'issued' | 'expires'>): string   // the signed content, fields in fixed order
cardEvent(c: UnsignedCard): UnsignedCardEvent   // the unsigned event for a card, ready for a signer

interface BondHandshake { v?: 1; pubkey: string; displayName?: string; nonce: string; personas?: { pubkey: string; label?: string }[] }
interface Box { p: string; claim: string; card: string; carriers?: string[] }
```

### Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `CARD_KIND` | 21641 | event kind of a card |
| `MAX_CARD_BYTES` | 16384 | longest encoded card, measured on the text after `#` |
| `MAX_AGE_SECONDS` | 2592000 | longest card lifetime, 30 days |
| `MAX_RELAYS` | 8 | relays on a card |
| `MAX_BOXES` | 4 | boxes on a card |
| `MAX_NAME` | 100 | longest name, display name or persona label, in code points |
| `MAX_PERSONAS` | 16 | personas in a bond |
| `LINK_CARD_MAX` | 4096 | longest Link card, in bytes |
| `LINK_CARD_MIN` | 126 | shortest Link card (no hints), in bytes |
| `LINK_CARD_MAX_AGE` | 604800 | longest Link card lifetime, 7 days |

## How a card is read

`readCard` runs five checks in order and returns the first that fails as
`{ ok: false, step, reason }`. A `now` that is not finite fails at step 3
(`clock`) before the card is decoded.

| Step | Checks | `reason` values |
|------|--------|-----------------|
| 1 | The text after the last `#` is 1 to `MAX_CARD_BYTES` long, decodes as base64url and strict UTF-8 JSON, is an event of kind 21641, and its content is JSON with `v` 1 | `size`, `decode`, `version` |
| 2 | The event's `pubkey`, `id` and `sig` are hex, it has exactly one tag and that tag is `expiration`, and the card's fields are valid: `rz`, `eph`, `name`, `relays`, `boxes`, `attest`, `bond` | `p`, `id`, `sig`, `tags`, `rz`, `eph`, `name`, `relays`, `boxes`, `box`, `box p`, `box claim`, `box card`, `box carriers`, `attest`, `bond` |
| 3 | `now` is finite; `created_at` and the `expiration` value are safe integers; the card has not expired; it expires after it was issued and within 30 days of it; it was not issued more than 300 seconds ahead of `now` | `clock`, `times`, `expired`, `expiry window`, `issued in the future` |
| 4 | The NIP-01 id matches the six event fields, and the BIP-340 signature verifies under `p` | `signature` |
| 5 | Each box's Link card decodes and passes `verifyLinkCard` rules 1 to 8 with no serial check, as `readCard` holds no highest serial | `link: decode`, or `link: ` followed by the reason of the failing rule |

## Link card rules

The numbered rules are those of
[forgesworn-link SPEC §2.3](https://github.com/forgesworn/forgesworn-link/blob/main/SPEC.md),
checked in this order, first failure reported. `verifyLinkCard` returns the
number as `rule`. `readCard` folds the reason into step 5 and `refreshBox`
returns the reason alone.

| Rule | Checks | `reason` values |
|------|--------|-----------------|
| 1 | Length is `LINK_CARD_MIN` to `LINK_CARD_MAX` bytes | `length` |
| 2 | Magic is `FSL1` and version is 1 | `magic or version` |
| 3 | Hint structure: at most 16 hints, each the right length for its kind, ending exactly at the signature, relay, onion and `0x04` contents valid, serial at most 2^53 - 1 | `hint count`, `hint runs past the signature`, `relay hint length`, `udp hint length`, `onion hint length`, `ephemeral hint length`, `relay hint utf-8`, `relay hint url`, `onion hint`, `ephemeral hint prefix`, `hints do not end at the signature`, `serial too large` |
| 4 | The signature verifies under the node id, strictly (`verifyStrict`) | `signature` |
| 5 | Not issued more than 300 seconds ahead of `now` (a `now` that is not finite also fails here) | `issued in the future`, `clock` |
| 6 | Not expired | `expired` |
| 7 | Expires after it was issued, and within `LINK_CARD_MAX_AGE` | `expiry window` |
| 8 | Serial is above `highestSerial`, when one is given (one that is not a safe integer also fails here) | `stale serial`, `highest serial is not an integer` |
| 9 | The node id is the pinned one. Applied only by `refreshBox`, not by `verifyLinkCard` | `node id is not the endorsed one` |

## Vectors

Vectors in `vectors/contact-card.json` are the draft's known-answer file:
thirty-two cards failing at each step, wrong kind and version, extra tag,
extra keys on the event and inside the signed content, tampered fields
and times, a foreign key, format characters, surrogates, byte-order
marks, empty fields and expiry windows, and six refresh cases including a
small-order node id and a nonce point carrying torsion. A second
implementation, written from the draft alone, must agree on every one;
the vectors carry the expected `ok` and step, and a verifier that
disagrees on either is wrong.

## What a card carries

More than two keys: the person's key `p`, their rendezvous key `rz`, a
fresh ephemeral, each box's key and Link node id (and so its onion
address), a display name, and a bond nonce that is a bearer secret for the
card's life: whoever holds the link can start the ceremony. The fragment
never reaches the server, but it does sit in browser history, clipboards,
chat logs and photographs of QR codes. Hand a card to the person it is
for.

Whoever holds it cannot derive rendezvous material from it, because the
derivation (in [nostr-deaddrop](https://github.com/forgesworn/nostr-deaddrop)) needs the reader's own secret or the
ephemeral's private half, and a card carries neither. It is never
identity: the box still decides admission, and a bond still needs the
ceremony.

## Security notes

- `readCard` returns only the named fields, every hex field lower-cased
  (bond and persona keys included), bond canonicalised. Names, display
  names and persona labels pass `isGoodName`: 1 to 100 code points, at
  least one visible, no control, surrogate, unassigned or private-use
  character, no separator but an ordinary space and none at the ends, no
  invisible or direction-changing format character, no run of five
  combining marks; the joiners and tag characters emoji need are allowed
  only beside a pictographic character. Empty strings are refused, because
  an empty name or attest would hash the same as none.
- The wire is decoded as strict UTF-8: a byte sequence that is not UTF-8,
  or a leading byte-order mark, is not a card. Nothing decodes to U+FFFD.
- Link cards are verified as libsodium and ed25519-dalek's `verify_strict`
  do: canonical encodings only (no ZIP-215), a node id or nonce point of
  small order refused, `S` below the group order, and the cofactorless
  equation `[S]B = R + [k]A`. noble's own `verify` multiplies by the
  cofactor and would accept a node id or nonce carrying torsion that a
  strict verifier refuses, so the check is done by hand (`verifyStrict`).
- Relay hints and card relays pass `isRelayUrl`: `wss://`, a URL with a
  DNS name or IP literal as host, no credentials, no fragment, no comma, no
  unprintable character, no byte-order mark. Onion hints are a 56-character
  base32 host with a non-zero port. An ephemeral hint (kind 0x04) has a
  compressed-point prefix. Kind 0x02 and unknown kinds come back in `hints`
  exactly as the box wrote them; only `relays` and `onions` are checked
  views. A serial above 2^53 - 1 is refused under Link card rule 3, before
  the signature.
- `now` must be a finite number of Unix seconds and `highestSerial` a safe
  integer or absent. Anything else fails closed; it never switches a check
  off. `Date.now()` milliseconds are finite, so they are not refused: they
  make every card and Link card read as expired, and a card built with a
  millisecond `now` is refused by every reader as issued in the future.
  Leaving `highestSerial` out is the one way to switch a check off, and it
  is yours to avoid (see below).
- The signature is the event's, over its NIP-01 id, and the content is
  signed byte for byte as carried. A key the draft does not name never
  reaches the caller, whether it sits on the event outside the signature
  or inside the signed content. The event carries exactly one tag,
  `expiration`; a second tag is refused before the signature is looked
  at. `buildCardWith` refuses a signer that returns
  anything but the event it was asked to sign.
- Hex case in the id and signature is normalised and base64url padding
  tolerated, so one card has several wire forms. Anything that caches or
  deduplicates on the encoded string must key on the card's fields, not
  its bytes.
- The size cap applies to the card, not the link it rides on. A contact
  card's `issued` may be up to 300 seconds ahead of `now`, and `expires`
  must be after `issued`.
- Replay protection for a box's fresh Link cards is Link card rule 8 (see
  [Link card rules](#link-card-rules)), and rule 8 needs the highest serial
  this client accepted for that node id. The
  library pins nothing: persist `link.serial` per node id and pass it to
  `refreshBox`; without it any unexpired old card of the same node is
  accepted.

## What remains

In the profile's own words, from its table of what remains: a card is
trusted on first use. An impostor who hands you a card is an impostor
you have a contact for; what narrows that is not in this library but in
how many independent channels confirm the key, shown as a count and never
as a score, and a bond ceremony spoken live. Whoever holds a card holds
its bond nonce, a bearer secret for the card's life.

## Licence

MIT. ForgeSworn.
