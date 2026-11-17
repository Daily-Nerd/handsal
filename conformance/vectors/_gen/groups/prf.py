"""Vectors prf/*: the cross-edition cases the tree can build with two editions (GP-22 to GP-24, CF-08).

P1 is the previous edition and P2 the current core. The fifteen rows below use fixture keys and the fixture profile
of each edition, so the generator writes them; the two owner-signed cases of the group (`prf/prodk-*`) are written
by the owner's signing run (lib/prodk.py) through the same builders. The shapes live in lib/editions.py, the one
owner of what a lineage over two editions looks like. The group has nothing to say when the tree holds one edition,
and says so: `Pair` fails the run.
"""
from lib import editions

ROWS = (
    ("prf/p1-org-folds-on-p2-release", editions.p1_organization),
    ("prf/change-p1-to-p2-ok", editions.change_ok),
    ("prf/change-p1-to-p2-quorum-unmet-under-p1", editions.change_quorum_unmet),
    ("prf/change-p1-to-p2-fork-path-under-p1", editions.change_fork_path),
    ("prf/second-change-same-edition-ok", editions.second_change),
    ("prf/downgrade-refused", editions.downgrade_refused),
    ("prf/downgrade-after-migration", editions.downgrade_after_migration),
    ("prf/order-downgrade-before-class", editions.downgrade_before_class),
    ("prf/order-fixture-before-downgrade", editions.fixture_before_downgrade),
    ("prf/mixed-kind-across-editions", editions.mixed_kind),
    ("prf/migration-reprofiled-document-valid", editions.reprofiled_document_valid),
    ("prf/pin-spec-older-edition-not-last-doc", editions.pin_names_older_edition),
    ("prf/p2-successor-supersedes-p1-pin", editions.successor_supersedes_pin),
    ("prf/recheck-p1-epoch-act-after-repin-to-p2", editions.recheck_after_repin),
    ("prf/render-change-across-editions", editions.render_change),
)


def generate(ctx):
    pair = editions.Pair(editions.FIXTURE)
    for name, build in ROWS:
        build(ctx, name, pair)
