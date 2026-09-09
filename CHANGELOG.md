# Changelog

## 0.1.0

- Second review pass (2026-09-09): `now` and `highestSerial` fail closed
  when not numbers; Ed25519 verified cofactorless by hand (`verifyStrict`),
  refusing torsion in the node id or nonce point; strict UTF-8 decode, no
  U+FFFD, no BOM; `isRelayUrl` for hints and card relays; `isGoodName`
  with emoji sequences allowed and hidden joiners refused; empty name,
  attest and carriers refused; `expires` must follow `issued`; serial
  above 2^53 reported under rule 3; 0x04 hint prefix checked; bond hex
  normalised; `refreshBox` accepts a byte pin and names a bad one.

- Independent review (2026-09-09), all findings applied: `readCard`
  returns a whitelisted card (extra keys and `__proto__` dropped); bond
  handshakes fully validated (`cleanBond`); names, display names and
  labels bounded and free of format characters; box card and carriers
  constrained to their alphabets so digest inputs carry no separators;
  size cap measured on the card, not the link; Link cards verified
  strictly (no ZIP-215, small-order node ids refused), hint contents
  checked, serials above 2^53 refused. Tests for each; README corrected.

- buildCard, readCard, cardLink, refreshBox; FSL-CARD-1 verify and build; canonical bond bytes; vectors.
