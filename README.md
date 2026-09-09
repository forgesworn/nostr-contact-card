# nostr-contact-card

**One QR or link that makes a stranger a contact, names their box, and starts a bond.**

A contact card is a small signed JSON object carried after `#` in a link or
as the whole of a QR code. It holds a person's key and name, their public
relays, their box (a Link address card, carried opaquely, that the person's
signature endorses), a rendezvous key and a fresh ephemeral for deriving
private rendezvous material, an optional attestation pointer, and a bond
handshake so an in-person ceremony can start from the card.

Reading a card needs nothing from the network: five checks, in order, and
the result names the step that failed so the client can say why. Dialling
the box afterwards is on the person's own word; a later fresh address from
the box is accepted only under the node id they endorsed.

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
ten cards, one failing at each step, and three refresh cases.

## What a card is not

A capability to reach a box and two public keys. Whoever holds it cannot
derive rendezvous material, because that needs the reader's own secret or
the ephemeral's private half, and a card carries neither. It is never
identity: the box still decides admission, and a bond still needs the
ceremony.

## Licence

MIT. ForgeSworn.
