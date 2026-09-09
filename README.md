# nostr-contact-card

**One QR or link that makes a stranger a contact, names their box, and starts a bond.**

A contact card is a small signed JSON object carried after `#` in a link or
as the whole of a QR code. It holds a person's key and name, their public
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
import { buildCard, cardLink, readCard, refreshBox } from 'nostr-contact-card'

const card = buildCard({ identityPrivateKey, rz, ephemeralPrivateKey, name: 'Ada', relays, boxes: [box], bond })
const link = cardLink('https://your.app/join', card)     // the server never sees the fragment

const r = readCard(scannedText, now())
if (!r.ok) show(r.step, r.reason)
else { addContact(r.card.p, r.card.name); for (const b of r.boxes) dial(b.link, b.box.p) }

const fresh = refreshBox(pinnedNodeId, freshLinkCardBytes, now(), highestSerialSeen)
```

Vectors in `vectors/contact-card.json` are the draft's known-answer file:
cards failing at each step, extra-key, format-character, surrogate,
byte-order-mark, empty-field and expiry-window cases, and refresh cases
including a small-order node id and a nonce point carrying torsion. A
second implementation, written from the draft alone, must agree on every
one; the vectors carry the expected `ok` and step, and a verifier that
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
- Hex case is normalised and base64url padding tolerated, so one card has
  several wire forms; so does any JSON re-serialisation. Anything that
  caches or deduplicates on the encoded string must key on the card's
  fields, not its bytes.
- The size cap applies to the card, not the link it rides on. A contact
  card's `issued` may be up to 300 seconds ahead of `now`, and `expires`
  must be after `issued`.
- Replay protection for a box's fresh Link cards is rule 8, and rule 8
  needs the highest serial this client accepted for that node id. The
  library pins nothing: persist `link.serial` per node id and pass it to
  `refreshBox`; without it any unexpired old card of the same node is
  accepted.

## Licence

MIT. ForgeSworn.
