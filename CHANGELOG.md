# Changelog

## 0.1.0

- Independent review (2026-09-09), all findings applied: `readCard`
  returns a whitelisted card (extra keys and `__proto__` dropped); bond
  handshakes fully validated (`cleanBond`); names, display names and
  labels bounded and free of format characters; box card and carriers
  constrained to their alphabets so digest inputs carry no separators;
  size cap measured on the card, not the link; Link cards verified
  strictly (no ZIP-215, small-order node ids refused), hint contents
  checked, serials above 2^53 refused. Tests for each; README corrected.

- buildCard, readCard, cardLink, refreshBox; FSL-CARD-1 verify and build; canonical bond bytes; vectors.
