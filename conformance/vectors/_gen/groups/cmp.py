"""Vectors cmp/*: `compact`, what a store may drop (CF-14, design 21.2).

The input is the CF-13 snapshot `{acts, docs, org}` of ORG and nothing else; the anchor is `{drop, reason}`, `drop` the
pair of sorted lists `acts` (strings of `acts`) and `sigs` (receipts of a document) that no fold reads. The stores are
built in lib/dropscenes.py and the lists are the author's statement of the complement of the retained set, made from
the spec (CF-06); no checker is asked. Before a row is written the whole-set guard runs: the generator's own fold
(lib/foldmodel.py) must give every leaf document of the input the same answer over the input and over the input
without the drop, so a list that contradicts the fold never becomes a vector.

`cmp/store-doc-invalid` and `cmp/store-original-wrong-org` are the refusals: a store whose second document lists its
members out of order is `doc_not_sorted`, and one whose original is another organization's is `lineage_broken`; the
answer carries no drop (CF-14: the store checks are those of CF-11).
"""
from lib import chain, dropscenes, result


def generate(ctx):
    w = ctx.writer
    for name, build in dropscenes.CMP:
        scene = build(ctx)
        scene.check()
        w.add(name, "compact", scene.anchor(), input=scene.input())
    refused = dropscenes.store_doc_invalid(ctx)
    w.add("cmp/store-doc-invalid", "compact", result.line({"drop": None, "reason": "doc_not_sorted"}),
          input=refused.input())
    # CF-14: the store checks are those of CF-11, so a snapshot whose original is another organization's is refused
    chain.Chain(ctx.fixtures, ctx=ctx, wit=True)   # the receipts of the other original go to the vitni cross-check
    w.add("cmp/store-original-wrong-org", "compact", result.line({"drop": None, "reason": "lineage_broken"}),
          input={"acts": [], "docs": ctx.fixtures.lineage(wit=True), "org": ctx.fixtures.org_id})
