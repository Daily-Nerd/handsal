# Errata

This file records editorial fixes to the core files between rule editions. It is not a core file and a fix recorded here moves no profile hash (CF-01).

An erratum never changes what any verifier, signer or consumer answers: a fix that would is a rule change and ships only as an edition (CF-01).

After the founding tag an editorial fix to a core file ships only together with a rule change, which is a new edition; until then it is recorded here, and a reader takes the fix from here.

## CF-11 Output: which act text `store` holds

Where: `spec/profile-interfaces.md`, CF-11, the Output paragraph, "S is the item with only the kept signatures".

Read it together with the Why paragraph of CF-11 (line 692), which says a store must not admit what its own retained set would drop, and with the kept signatures paragraph (line 686), which defines kept as what the retained set of CF-14 keeps. Under CF-14 item 5 the retained set holds one text per receipt id, the smaller valid one. So "the item" in the Output sentence means the item as the retained set of the grown store keeps it:

- `act` is the copy of the act that the retained set keeps. That is the item's own text, or, when the store already holds another text of the same receipt id that the retained set prefers (a smaller valid twin), that stored text. A caller writes it create-only, so a text already stored is a no-op that reports success.
- `sigs` are the item's own texts that the retained set keeps. A text of the item that has a smaller valid twin already stored is left out.

No answer code changes, and an answer where the store already agrees with its retained set is the same as before. The wording was loose about this, so the sentence is clarified here and nothing else moves.
