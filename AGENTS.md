# nostr-contact-card

Builds, signs, reads and refreshes Nostr contact cards: signed events of
kind 21641, in the ephemeral range and never posted to a relay, carried
after `#` in a link or as the whole of a QR code. Zero runtime
dependencies beyond `@noble/curves`, `@noble/hashes` and `@scure/base`;
targets Node >=22 and browsers.

## Build & Test

| Command | Purpose |
|---------|---------|
| `npm ci` | Install dependencies |
| `npm run build` | Compile to `dist` (`tsc -p tsconfig.build.json`) |
| `npm test` | Run the vitest suite |
| `npm run typecheck` | Type-check without emitting |

## Structure

```
src/card.ts       contact card build, sign, read, encode, refresh
src/link-card.ts  Link card verification and building (boxes)
src/index.ts      public exports
test/             vitest suite
vectors/          known-answer vectors for a second implementation
```

## Conventions

- British English in prose and comments.
- No third-party runtime dependencies beyond the three noble/scure packages
  already listed in `package.json`.
- `readCard` never returns a field the draft does not name, even when one
  arrives on the wire outside or inside the signed content.
- Link card verification uses the strict, cofactorless equation
  (`verifyStrict`), not noble's cofactored `verify`.

## Key Files

| File | Purpose |
|------|---------|
| `src/card.ts` | Card build, sign, read, refresh and the constants (`CARD_KIND`, `MAX_CARD_BYTES`, etc.) |
| `src/link-card.ts` | Box's Link card: `verifyLinkCard`, `buildLinkCard`, `isRelayUrl` |
| `vectors/contact-card.json` | Known-answer vectors a second implementation must agree with |

## Common Pitfalls

- Do not weaken `readCard`'s five ordered checks or change what step a
  failure reports; the vectors pin both the `ok` result and the step.
- Do not change the vectors in `vectors/contact-card.json`; they are the
  draft's known-answer file, not test fixtures to adjust for convenience.
- `refreshBox` needs the highest serial the client already accepted for a
  node id; without it, any unexpired old Link card of that node is
  accepted.
