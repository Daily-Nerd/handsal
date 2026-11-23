"""T4.4: the section 11 reason code index against the checker and the vectors (CF-07, spec 16.9).

The code list comes from `tools/check_catalog.py`, the one owner of how the
spec index is read. A code is the checker's when a row other than a signer
exit code or a pin helper row lists it.
"""
import ast
import importlib.util
import json
import unittest
from pathlib import Path

from .checkact_world import NOW, Scenario, at, dave_world
from .test_enrolled import production_world, relay_scenario, run as enrolled_answer, stmt, value

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "checker" / "python" / "src" / "handsal_check"


def tools_module(name):
    spec = importlib.util.spec_from_file_location("tools_" + name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CATALOG = tools_module("check_catalog")
SPEC = tools_module("manifest").read_profile(ROOT)

# Codes the checker raises before the spec index lists them: `{code: what lands with its row}`. A code is a visible entry
# here and nowhere else, never a constant the census cannot read. The census fails on an entry the index already lists
# (the change that adds the row deletes the entry) and on an entry the checker no longer raises (it does not outlive
# the code), so the list is empty the day the spec text it waits for lands.
PENDING_CODES = {}


def census_gaps(used, index, pending):
    """What is wrong between the codes the checker raises (`used`), the codes the spec index lists (`index`) and the
    codes allowed to precede their row (`pending`): `{kind: sorted codes}`, every list empty when nothing is."""
    return {"raised and neither indexed nor pending": sorted(used - index - set(pending)),
            "pending and already indexed": sorted(set(pending) & index),
            "pending and not raised": sorted(set(pending) - used)}


def package_strings():
    found = set()
    for path in sorted(PACKAGE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                found.add(node.value)
    return found


def module_of(filename):
    """The name other modules use for the module in `filename` (`subset.py` is `subset`). The one place that
    names it: the census and its small cases both give `refusal_codes` file names."""
    return Path(filename).stem


def refusal_codes(files):
    """The reason codes the modules `files` (`{file name: source text}`) raise: the codes of every call of
    `Refused`, plain or as `errors.Refused`, and of every call of a function that hands its first parameter to
    `Refused` (a wrapper). The code is a string literal, a module-level string constant of the same module, a
    `module.NAME` constant of another module of `sources`, or a conditional of those. A call that forwards a value
    read at run time (a name, an attribute, a subscript, a call) names no code of its own: the code was raised where
    it was written. Any other argument, a composed string for one, is an error, never skipped."""
    trees = {module_of(name): ast.parse(text) for name, text in files.items()}
    constants = {name: {node.targets[0].id: node.value.value for node in tree.body
                        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                        and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}
                 for name, tree in trees.items()}

    def callee(call):
        func = call.func
        return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None

    def first_is(call, name):
        return bool(call.args) and isinstance(call.args[0], ast.Name) and call.args[0].id == name

    refusing = {"Refused"}
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.args.args:
                first = node.args.args[0].arg
                if any(isinstance(c, ast.Call) and callee(c) == "Refused" and first_is(c, first) for c in ast.walk(node)):
                    refusing.add(node.name)

    def codes_of(expr, module):
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return {expr.value}
        if isinstance(expr, ast.Name) and expr.id in constants[module]:
            return {constants[module][expr.id]}
        if (isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name)
                and expr.attr in constants.get(expr.value.id, ())):
            return {constants[expr.value.id][expr.attr]}
        if isinstance(expr, ast.IfExp):
            return codes_of(expr.body, module) | codes_of(expr.orelse, module)
        if isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
            return set()
        raise ValueError("%s: the code of a refusal is read from %s" % (module, ast.unparse(expr)))

    used = set()
    for module, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and callee(node) in refusing and node.args:
                used |= codes_of(node.args[0], module)
    return used


class RefusalCensus(unittest.TestCase):
    """What `refusal_codes` sees, on small sources: a code that is raised and not read is a code the index could lack."""

    def codes(self, **sources):
        return refusal_codes({name + ".py": text for name, text in sources.items()})

    def test_a_literal_is_seen(self):
        self.assertEqual(self.codes(m='raise Refused("a_code")'), {"a_code"})

    def test_a_call_through_the_errors_module_is_seen(self):
        self.assertEqual(self.codes(m='raise errors.Refused("a_code")'), {"a_code"})

    def test_a_module_constant_of_the_same_module_is_seen(self):
        self.assertEqual(self.codes(m='X = "a_code"\nraise Refused(X)'), {"a_code"})

    def test_a_constant_of_another_module_is_seen(self):
        self.assertEqual(self.codes(m="raise errors.Refused(other.X)", other='X = "a_code"'), {"a_code"})

    def test_the_census_input_shape_resolves_a_constant_of_another_module(self):
        """The shape the real census builds: file names, `subset.py`, read through `subset.NOT_CANONICAL`."""
        files = {"envelope.py": "raise errors.Refused(subset.NOT_CANONICAL)", "subset.py": 'NOT_CANONICAL = "a_code"'}
        self.assertEqual(refusal_codes(files), {"a_code"})
        self.assertEqual(refusal_codes({k: files[k] for k in ("envelope.py",)}), set())

    def test_both_branches_of_a_conditional_are_seen(self):
        self.assertEqual(self.codes(m='raise Refused("a" if x else "b")'), {"a", "b"})

    def test_a_literal_given_to_a_wrapper_is_seen(self):
        self.assertEqual(self.codes(m='def refuse(code):\n    return errors.Refused(code)\nraise refuse("a_code")'),
                         {"a_code"})
        self.assertEqual(self.codes(m="def refuse(code):\n    return errors.Refused(code)", n='raise m.refuse("a_code")'),
                         {"a_code"})

    def test_a_forwarded_value_is_no_code_of_its_own(self):
        self.assertEqual(self.codes(m="raise Refused(err.reason)\nraise Refused(found[0])\nraise Refused(f(x))"
                                      "\nraise Refused(code)"), set())

    def test_a_composed_code_is_an_error(self):
        for text in ('raise Refused("a_" + kind)', 'raise Refused(f"a_{kind}")'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.codes(m=text)


class PendingCodes(unittest.TestCase):
    """The one allowance of the census, and the three ways it can be wrong."""

    NONE = {"raised and neither indexed nor pending": [], "pending and already indexed": [], "pending and not raised": []}

    def test_a_pending_code_that_is_raised_and_not_indexed_is_allowed(self):
        self.assertEqual(census_gaps({"a", "p"}, {"a"}, {"p": "why"}), self.NONE)

    def test_a_raised_code_that_is_neither_indexed_nor_pending_is_a_gap(self):
        self.assertEqual(census_gaps({"a", "z"}, {"a"}, {})["raised and neither indexed nor pending"], ["z"])

    def test_a_pending_code_the_index_lists_is_a_gap(self):
        self.assertEqual(census_gaps({"a"}, {"a"}, {"a": "why"})["pending and already indexed"], ["a"])

    def test_a_pending_code_the_checker_does_not_raise_is_a_gap(self):
        self.assertEqual(census_gaps({"a"}, {"a"}, {"p": "why"})["pending and not raised"], ["p"])

    def test_every_pending_code_says_what_lands_with_its_row(self):
        for code, why in PENDING_CODES.items():
            self.assertTrue(why.strip(), code)


class ReasonCodeIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codes, cls.retired, cls.excepted = CATALOG.spec_codes(SPEC)
        cls.mine = CATALOG.checker_codes(SPEC)
        cls.strings = package_strings()
        cls.shown = CATALOG.anchor_codes(ROOT, include_ordering=True)

    def test_every_checker_code_exists_in_the_checker(self):
        missing = [c for c in self.mine if c not in self.strings]
        self.assertEqual(missing, [])

    def test_every_checker_code_is_in_an_anchor_or_excepted(self):
        # No ledger of codes "waiting for a vector": a code the checker returns either has an
        # only-defect vector on disk or is excepted in CF-07 with its reason.
        missing = [c for c in self.mine if c not in self.shown and c not in self.excepted]
        self.assertEqual(sorted(missing), [])

    def test_an_excepted_checker_code_is_a_real_checker_code(self):
        for code in self.excepted & set(self.mine):
            self.assertIn(code, self.strings)

    def test_every_other_excepted_code_belongs_to_the_pin_helper_or_the_signer(self):
        # CF-07 excepts a component code only because no vector input sets it up; the checker never returns it.
        others = self.excepted - set(self.mine)
        self.assertEqual(sorted(others), ["biometric_unavailable", "internal", "key_exists", "key_unavailable",
                                          "no_display", "pin_invalid", "pin_rollback", "profile_not_current",
                                          "prompt_refused", "user_cancel"])
        for code in others:
            self.assertIn(code, self.codes)
            self.assertNotIn(code, self.shown, "a code with a vector needs no exception: %s" % code)

    def test_no_retired_code_is_left_in_the_checker_or_a_vector(self):
        self.assertEqual(self.retired, {"genesis_signer_unknown", "genesis_sig_mismatch", "genesis_head_mismatch"})
        self.assertEqual(sorted(self.retired & self.strings), [])
        self.assertEqual(sorted(self.retired & self.shown), [])
        self.assertFalse(self.retired & set(self.codes))

    def test_the_edition_codes_are_indexed_in_their_place(self):
        """GP-24, SG-17, section 11: `profile_downgrade` is a fold code after `fixture_profile` and before
        `policy_invalid`; `profile_not_current` is a signer code of exit 2, not a checker code."""
        order = [c for c in self.codes if c in ("profile_mismatch", "fixture_profile", "profile_downgrade", "policy_invalid")]
        self.assertEqual(order, ["profile_mismatch", "fixture_profile", "profile_downgrade", "policy_invalid"])
        self.assertIn("profile_downgrade", self.mine)
        self.assertNotIn("profile_downgrade", self.excepted)
        self.assertIn("profile_not_current", self.codes)
        self.assertNotIn("profile_not_current", self.mine)
        self.assertIn("profile_not_current", self.excepted)

    def test_the_store_drop_codes_are_indexed_with_their_commands(self):
        """Design 21.9, section 11: `epoch_superseded` (view rule, `enrolled`, `sync`) and `epoch_closed` (`admit`)."""
        self.assertIn("epoch_superseded", self.mine)
        self.assertIn("epoch_closed", self.mine)
        rows = {code: where for row, where in CATALOG._table_rows(CATALOG._section(SPEC, "## 11. Reason codes")) for code in row}
        self.assertIn("VR-12", rows["epoch_superseded"])
        self.assertIn("`sync` (CF-09)", rows["epoch_superseded"])
        self.assertEqual(rows["epoch_closed"], "`admit` (CF-11)")

    def test_every_code_head_can_answer_names_head_in_the_index(self):
        """Design 22.4, VR-19: `head` runs the pin checks, the fold, the view and the witness rules, so the
        rows of those codes name it beside `check-act` and `enrolled`; a code only `head` could use has no row."""
        rows = {code: where for row, where in CATALOG._table_rows(CATALOG._section(SPEC, "## 11. Reason codes")) for code in row}
        for code in ("pin_org_mismatch", "pin_missing", "pin_owner", "pin_malformed", "profile_mismatch", "fixture_profile",
                     "genesis_pin_mismatch", "pin_spec_mismatch", "lineage_broken",
                     "view_in_future", "stale_view", "epoch_superseded",
                     "witness_unexpected", "witness_missing", "stale_witness", "behind_witness",
                     "store_missing", "store_owner", "store_malformed", "store_unavailable"):
            with self.subTest(code=code):
                self.assertIn(code, rows)
                self.assertIn("`head` (VR-19)", rows[code])
        folds = CATALOG._line(CATALOG._section(SPEC, "## 11. Reason codes"), "| fold error codes (below)")
        self.assertIn("`head` (VR-19)", folds)

    def test_no_code_the_checker_returns_is_missing_from_the_index(self):
        # Every code handed to Refused(...), errors.Refused(...) or a wrapper of it is in the index.
        index = set(self.codes) | self.retired
        used = refusal_codes({path.name: path.read_text(encoding="utf-8") for path in sorted(PACKAGE.glob("*.py"))})
        self.assertEqual(census_gaps(used, index, PENDING_CODES), PendingCodes.NONE)
        # A census that collapsed to blind would pass the line above: it must still see a code written as a
        # constant of another module (`errors.Refused(subset.NOT_CANONICAL)` in envelope.py), and most of the index.
        self.assertIn("payload_not_canonical_subset", used)
        self.assertGreater(len(used), 75)


class ReasonClassCensus(unittest.TestCase):
    """`conformance/reason-classes.json` against the section 11 index: it names every code once as a default and no
    code the index does not have. It is read as data here, the checker imports nothing from `tools/` at run time."""

    @classmethod
    def setUpClass(cls):
        cls.index = set(CATALOG.spec_codes(SPEC)[0])
        cls.table = json.loads((ROOT / "conformance" / "reason-classes.json").read_text(encoding="utf-8"))

    def test_every_index_code_has_a_default_class(self):
        self.assertEqual(sorted(self.index - set(self.table["default"])), [])

    def test_the_two_codes_of_the_edition_are_admission_for_the_command_that_gives_them(self):   # CF-03 section 11
        classes = tools_module("reason_classes")
        table = classes.load()
        self.assertEqual(classes.classify("admit", "evidence_missing", table), "admission")
        self.assertEqual(classes.classify("sync", "snapshot_incomplete", table), "admission")
        for code in ("evidence_missing", "snapshot_incomplete"):   # a default row, no `by_command` row
            self.assertEqual(self.table["default"][code], "admission")
            self.assertEqual([c for c, rows in self.table["by_command"].items() if code in rows], [])

    def test_no_row_names_a_code_the_index_does_not_have(self):
        named = set(self.table["default"])
        for per_command in self.table["by_command"].values():
            named |= set(per_command)
        self.assertEqual(sorted(named - self.index), [])

    def test_every_class_a_row_names_is_one_of_the_nine(self):
        classes = set(self.table["classes"])
        self.assertEqual(len(classes), 9)
        used = set(self.table["default"].values())
        for per_command in self.table["by_command"].values():
            used |= set(per_command.values())
class EnrolledAnswerClass(unittest.TestCase):
    """Pin of existing behavior (GP-13 steps 5 and 6, VR-12): over a fixed store and pin, the three inputs a clock
    moves (`now`, `synced_at`, `tip_statement`) only move the `enrolled` answer among `ok`, the same membership
    answer, and freshness-class codes. It asserts the class, never which of two failures shows (step order decides
    that). A membership code that turned time-dependent fails here."""

    NOWS = (NOW, at(-86401 * 2), at(5), at(-10 ** 7))
    SYNCED = (at(0), at(86400), at(86401), at(-301), at(10 ** 7))

    @classmethod
    def setUpClass(cls):
        cls.classes = tools_module("reason_classes")
        cls.table = cls.classes.load()

    def kind(self, code):
        return self.classes.classify("enrolled", code, self.table)

    def grid(self, base, tips, production=True):
        """The `enrolled` reasons over every (now, synced_at, tip_statement), the store, pin and device being fixed."""
        found = []
        for now in self.NOWS:
            for synced_at in self.SYNCED:
                for tip in tips:
                    got = enrolled_answer(dict(base, now=now, synced_at=synced_at, tip_statement=tip),
                                          production=production)
                    found.append(got["reason"])
        return found

    def test_an_enrolled_device_moves_only_between_ok_and_freshness(self):
        plain = Scenario(production_world())
        relay = relay_scenario()
        for name, s, tips in (("no witness", plain, (None, "whatever")),
                              ("relay witness", relay, (None, "whatever", stmt(relay)))):
            with self.subTest(world=name):
                kinds = {self.kind(code) for code in self.grid(value(s), tips)}
                self.assertEqual(kinds - {"ok", "freshness"}, set())
                self.assertEqual(kinds, {"ok", "freshness"})

    def test_an_unknown_device_stays_local_key_unknown_whatever_the_clock_says(self):
        s = Scenario(production_world())
        self.assertEqual(set(self.grid(value(s, device_kid="A" * 43), (None, "whatever"))), {"local_key_unknown"})
        self.assertEqual(self.kind("local_key_unknown"), "membership")

    def test_a_removed_device_stays_local_key_not_active_whatever_the_clock_says(self):
        s = Scenario(production_world())
        gone = s.w.device_remove("alice", ("bob", "carol"))
        self.assertEqual(set(self.grid(value(s, acts=gone.acts), (None, "whatever"))), {"local_key_not_active"})
        self.assertEqual(self.kind("local_key_not_active"), "membership")

    def test_a_device_of_an_unaccepted_class_stays_so_whatever_the_clock_says(self):
        w, step = dave_world()
        s = Scenario(w, ("alice", "bob", "carol", "dave"))
        base = value(s, device="dave2", acts=step.acts)
        self.assertEqual(set(self.grid(base, (None, "whatever"), production=False)), {"local_class_not_accepted"})
        self.assertEqual(self.kind("local_class_not_accepted"), "membership")


if __name__ == "__main__":
    unittest.main()
