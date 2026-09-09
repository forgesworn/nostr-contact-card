# nostr-contact-card

[![CI](https://github.com/forgesworn/nostr-contact-card/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/nostr-contact-card/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/nostr-contact-card)](https://www.npmjs.com/package/nostr-contact-card)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](./LICENCE)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

**One QR or link that makes a stranger a contact, names their box, and starts a bond.**

A contact card is a signed Nostr event of the reserved kind 30641, never
posted to a relay, carried after `#` in a link or as the whole of a QR
code. The event's pubkey is the person's key, its created_at is when the
card was issued, its expiration tag is when it lapses, and its content is
the card, so the signature is the one every signer already makes: an
extension, a bunker or a key held locally all make the same card. It holds a person's key and name, their public
relays, their box (a Link address card, carried opaquely, that the person's
signature endorses), a rendezvous key and a fresh ephemeral for deriving
private rendezvous material, an optional attestation pointer, and a bond
handshake so an in-person ceremony can start from the card.

Reading a card needs nothing from the network: five checks, in order, and
the result names the step that failed so the client can say why. What comes
back is rebuilt from the fields the draft names, each checked; an extra key
on the wire never reaches the caller under a verified signature. Dialling
the box afterwards is on the person's own word; a later fresh address from
the box is accepted only under the node id they endorsed, which the client
pins from the first read (the Link card inside a contact card lasts seven
days, the card itself thirty, so a client keeps the node id it read).

```ts
import { buildCard, buildCardWith, cardLink, readCard, refreshBox } from 'nostr-contact-card'

const card = buildCard({ identityPrivateKey, rz, ephemeralPrivateKey, name: 'Ada', relays, boxes: [box], bond })
// or, through a signer that holds the key (NIP-07, NIP-46):
const viaSigner = await buildCardWith(pubkey, (unsigned) => signer.signEvent(unsigned), { rz, ephemeralPrivateKey, name: 'Ada', relays, boxes: [box] })
const link = cardLink('https://your.app/join', card)     // the server never sees the fragment

const r = readCard(scannedText, now())
if (!r.ok) show(r.step, r.reason)
else { addContact(r.card.p, r.card.name); for (const b of r.boxes) dial(b.link, b.box.p) }

const fresh = refreshBox(pinnedNodeId, freshLinkCardBytes, now(), highestSerialSeen)
```

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
derivation (in nostr-deaddrop) needs the reader's own secret or the
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
  views. A serial above 2^53 is refused under rule 3, before the signature.
- `now` must be a finite number of seconds and `highestSerial` an integer
  or absent. Anything else fails closed; it never switches a check off.
- The signature is the event's, over its NIP-01 id, and the content is
  signed byte for byte as carried. A key the draft does not name never
  reaches the caller, whether it sits on the event outside the signature
  or inside the signed content. The event carries exactly a `d` tag of
  `card` and an `expiration` tag; a third tag is refused before the
  signature is looked at. `buildCardWith` refuses a signer that returns
  anything but the event it was asked to sign.
- Hex case in the id and signature is normalised and base64url padding
  tolerated, so one card has several wire forms. Anything that caches or
  deduplicates on the encoded string must key on the card's fields, not
  its bytes.
- The size cap applies to the card, not the link it rides on. A contact
  card's `issued` may be up to 300 seconds ahead of `now`, and `expires`
  must be after `issued`.
- Replay protection for a box's fresh Link cards is rule 8, and rule 8
  needs the highest serial this client accepted for that node id. The
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
