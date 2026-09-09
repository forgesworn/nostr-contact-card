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
cards failing at each step, extra-key and format-character cases, and
refresh cases including a small-order node id. A second implementation,
written from the draft alone, must agree on every one.

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

- `readCard` returns only the named fields, hex lower-cased, bond
  canonicalised. Names, display names and persona labels are at most 100
  code points with no control, format or separator characters.
- Link cards are verified strictly: RFC 8032 signature checks, no ZIP-215
  encodings, and a node id of small order is refused before the signature
  is looked at. Relay hints must be valid UTF-8 `wss://` URLs and onion
  hints a 56-character base32 host with a non-zero port; anything else
  fails the card. A serial above 2^53 is refused rather than rounded.
- Hex case is normalised and base64url padding tolerated, so one card has
  several wire forms. Anything that caches or deduplicates on the encoded
  string must key on the card's fields, not its bytes.
- The size cap applies to the card, not the link it rides on.

## Licence

MIT. ForgeSworn.
