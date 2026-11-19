# Errata

This file records editorial fixes to the core files between rule editions. It is not a core file and a fix recorded here moves no profile hash (CF-01).

An erratum never changes what any verifier, signer or consumer answers: a fix that would is a rule change and ships only as an edition (CF-01).

After the founding tag an editorial fix to a core file ships only together with a rule change, which is a new edition; until then it is recorded here, and a reader takes the fix from here.

## CF-11 Output: which act text `store` holds

Where: `spec/profile-interfaces.md`, CF-11, the Output paragraph, "S is the item with only the kept signatures".

Read it together with the Why paragraph of CF-11 (line 692), which says a store must not admit what its own retained set would drop, and with the kept signatures paragraph (line 686), which defines kept as what the retained set of CF-14 keeps. Under CF-14 item 5 the retained set holds one text per receipt id, the smallest valid one. So "the item" in the Output sentence means the item as the retained set of the grown store keeps it. The retained set keeps the smaller valid text of a receipt id, so a stored valid text wins over an invalid item text and over a larger valid one:

- `act` is the copy of the act that the retained set keeps. That is the item's own text, or, when the store already holds another text of the same receipt id that the retained set keeps instead (the stored text is the only valid one, or the smaller valid one), that stored text. A caller writes it create-only, so a text already stored is a no-op that reports success.
- `sigs` are the item's own texts that the retained set keeps. A text of the item that the retained set drops for a stored text of the same receipt id is left out.

The rule does not change. Line 692 and CF-14 item 5 already required this, and a verifier that follows them already answers this way, so no answer of such a verifier moves and no answer code changes. Only the Output sentence was loose, and this entry reads it as the rules above it already say. This repository's checker did not follow line 692 in these cases (an item text that the retained set drops, beside a stored text of the same receipt id) and is fixed in the same release. That is a statement about this one implementation, not a change of the rule.
