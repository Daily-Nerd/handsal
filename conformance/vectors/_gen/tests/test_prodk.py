"""T7.2 the production-key vectors (PRODK, CF-08, GP-18).

The six `fix/prodk-*` and `enr/prodk-*` vectors are signed once by production keys whose private scalars
exist only in the memory of the signing process. These tests run the builder with throwaway keys, so
they prove the shape and the secrecy rules without any production key:

- the six ids are the `pending` list of vector-ids.json (one owner of the list);
- no fixture kid is a device of ORG_PRODK, and no PRODK kid is on the fixture list;
- every document names the production profile;
- no output (vector, evidence) holds a scalar, in any of the forms a scalar could be written in;
- the builder refuses a directory that already holds files, so the keys cannot sign a second time.
"""
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import generate
from lib import base, keys, p256, prodk

GEN = Path(__file__).resolve().parents[1]
CONFORMANCE = GEN.parents[1]
LISTING = json.loads((CONFORMANCE / "vector-ids.json").read_text(encoding="utf-8"))
# the six ids of the owner run: the production-key cases of the pending list, never the `prf/` ids
OWNER_IDS = sorted(n for n in LISTING["pending"] if n.split("/", 1)[1].startswith("prodk-") and not n.startswith("prf/"))
FIXTURE_KIDS = set(json.loads((CONFORMANCE / "fixtures" / "fixture-kids.json").read_text(encoding="utf-8")))


def throwaway():
    """Deterministic entries so a test can compare two builds; a real run draws them from `secrets`."""
    counter = iter(range(1000, 2000))
    return prodk.random_entries(randbelow=lambda bound: next(counter))


class Draw(unittest.TestCase):
    def test_every_scalar_is_in_range_and_the_three_people_have_distinct_keys(self):
        entries = prodk.random_entries()
        signs = [entries[name + ".sign"] for name in prodk.PEOPLE]
        scalars = [int(e["d"], 16) for e in signs]
        for d in scalars:
            self.assertTrue(1 <= d <= p256.N - 1)
        self.assertEqual(len(set(scalars)), 3)
        kids = {e["kid"] for e in signs}
        self.assertEqual(len(kids), 3)

    def test_a_kid_is_the_thumbprint_of_its_public_key(self):
        entry = prodk.random_entries()["alice.sign"]
        x, y = p256.mul(int(entry["d"], 16))
        self.assertEqual((entry["x"], entry["y"]), (keys.b64u(x.to_bytes(32, "big")), keys.b64u(y.to_bytes(32, "big"))))
        self.assertEqual(entry["kid"], keys.thumbprint(entry["x"], entry["y"]))

    def test_the_agreement_keys_hold_no_scalar_because_nothing_ever_uses_one(self):
        entries = prodk.random_entries()
        for name in prodk.PEOPLE:
            self.assertEqual(int(entries[name + ".agree"]["d"], 16), 0)
            self.assertNotIn("kid", entries[name + ".agree"])

    def test_the_draw_comes_from_the_random_source_it_is_given(self):
        seen = []

        def source(bound):
            seen.append(bound)
            return 41
        entries = prodk.random_entries(randbelow=source)
        self.assertEqual(int(entries["alice.sign"]["d"], 16), 42)
        self.assertTrue(seen and all(bound == p256.N - 1 for bound in seen))

    def test_two_real_draws_differ(self):
        self.assertNotEqual(prodk.random_entries()["alice.sign"]["kid"], prodk.random_entries()["alice.sign"]["kid"])

    def test_the_scalars_to_destroy_are_the_three_signing_scalars(self):
        entries = throwaway()
        self.assertEqual(sorted(prodk.scalars(entries)), sorted(int(entries[n + ".sign"]["d"], 16) for n in prodk.PEOPLE))


class OwnerRun(unittest.TestCase):
    """`pending` of vector-ids.json holds two kinds of id: those that wait for the owner run and those that wait
    for a second edition (`prf/`, CF-08 S8). The owner run selects the first kind and nothing else."""

    def test_the_owner_run_ids_are_exactly_the_six_owner_signed_ids_while_prf_ids_are_pending(self):
        self.assertTrue(any(n.startswith("prf/") for n in LISTING["pending"]))
        self.assertEqual(prodk.pending_ids(), OWNER_IDS)
        self.assertEqual(len(OWNER_IDS), 6)

    def test_the_owner_run_ids_come_from_the_rule_of_the_catalog_check(self):
        cc = prodk.catalog_check()
        self.assertEqual(set(prodk.pending_ids()), cc.owner_signed_ids(CONFORMANCE.parent))


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name) / "prod"
        cls.entries = throwaway()
        cls.names = prodk.build(cls.dir, cls.entries)
        cls.docs = {json.loads(p.read_text())["name"]: json.loads(p.read_text()) for p in cls.dir.glob("*.json")}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_ids_are_exactly_the_pending_ids_of_the_listing(self):
        self.assertEqual(set(self.docs), set(OWNER_IDS))
        self.assertEqual(sorted(self.names), sorted(OWNER_IDS))
        self.assertEqual(len(self.docs), 6)

    def test_the_files_are_named_group_dot_case(self):
        self.assertEqual(sorted(p.name for p in self.dir.glob("*.json")),
                         sorted(n.replace("/", ".") + ".json" for n in OWNER_IDS))

    def test_every_document_names_the_production_profile_and_no_fixture_profile(self):
        production, fixture = base.production_profile(), base.fixture_profile()
        for name, doc in self.docs.items():
            text = json.dumps(doc)
            self.assertIn(production, text, name)
            self.assertNotIn(fixture, text, name)

    def test_the_organization_lists_only_the_three_production_keys(self):
        want = {self.entries[n + ".sign"]["kid"] for n in prodk.PEOPLE}
        doc = self.docs["fix/prodk-fold-ok"]["input"]["lineage"][-1]["doc"]
        self.assertEqual({d["kid"] for d in doc["devices"]}, want)
        self.assertFalse(want & FIXTURE_KIDS)

    def test_a_fixture_kid_is_never_a_device_of_the_organization(self):
        for name in ("fix/prodk-fold-ok", "fix/prodk-check-act-ok", "enr/prodk-fixture-kid-unknown"):
            doc = self.docs[name]["input"]["lineage"][-1]["doc"]
            self.assertFalse({d["kid"] for d in doc["devices"]} & FIXTURE_KIDS, name)

    def test_the_fold_ok_state_lists_the_three_production_keys_and_the_production_profile(self):
        state = json.loads(self.docs["fix/prodk-fold-ok"]["anchor"])
        self.assertEqual(state["spec"], base.production_profile())
        kids = {kid for person in state["keys"].values() for kid in person}
        self.assertEqual(kids, {self.entries[n + ".sign"]["kid"] for n in prodk.PEOPLE})

    def test_the_check_act_ok_vector_is_an_approve_by_the_production_alice(self):
        doc = self.docs["fix/prodk-check-act-ok"]
        self.assertEqual(doc["command"], "check-act")
        self.assertEqual(json.loads(doc["anchor"])["reason"], "ok")
        header = json.loads(base64.urlsafe_b64decode(doc["input"]["jws"].split(".")[0] + "=="))
        self.assertEqual(header["kid"], self.entries["alice.sign"]["kid"])

    def test_the_fixture_kid_add_leaves_the_state_as_it_was(self):
        added = self.docs["fix/prodk-fixture-kid-add-not-on-chain"]
        plain = self.docs["fix/prodk-fold-ok"]
        self.assertGreater(len(added["input"]["acts"]), 0)
        self.assertEqual(json.loads(added["anchor"]), json.loads(plain["anchor"]))

    def test_the_fixture_kid_approve_is_an_unknown_key_signed_by_a_fixture_kid(self):
        doc = self.docs["fix/prodk-check-act-fixture-kid-unknown"]
        self.assertEqual(json.loads(doc["anchor"])["reason"], "unknown_key")
        kid = json.loads(base64.urlsafe_b64decode(doc["input"]["jws"].split(".")[0] + "=="))["kid"]
        self.assertIn(kid, FIXTURE_KIDS)

    def test_the_relay_vector_is_a_fold_that_ends_in_fixture_key(self):
        doc = self.docs["fix/prodk-relay-fixture-kid"]
        self.assertEqual((doc["command"], json.loads(doc["anchor"])), ("fold", {"error": "fixture_key"}))
        witness = doc["input"]["lineage"][-1]["doc"]["policy"]["witness"]
        self.assertIn(witness["relay_kid"], FIXTURE_KIDS)

    def test_the_enrolled_vector_asks_about_a_fixture_kid(self):
        doc = self.docs["enr/prodk-fixture-kid-unknown"]
        self.assertEqual(json.loads(doc["anchor"]), {"enrolled": False, "reason": "local_key_unknown"})
        self.assertIn(doc["input"]["device_kid"], FIXTURE_KIDS)

    def test_the_same_keys_give_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as other:
            out = Path(other) / "prod"
            prodk.build(out, self.entries)
            for path in self.dir.glob("*.json"):
                self.assertEqual(path.read_bytes(), (out / path.name).read_bytes(), path.name)

    def test_other_keys_give_other_bytes(self):
        with tempfile.TemporaryDirectory() as other:
            out = Path(other) / "prod"
            prodk.build(out, prodk.random_entries())
            self.assertNotEqual((out / "fix.prodk-fold-ok.json").read_bytes(),
                                (self.dir / "fix.prodk-fold-ok.json").read_bytes())

    def test_no_output_holds_a_scalar(self):
        self.assertEqual(prodk.scan(prodk.scalars(self.entries), [self.dir]), [])

    def test_a_directory_that_holds_files_is_refused_so_the_keys_cannot_sign_twice(self):
        with self.assertRaises(prodk.ProdkError):
            prodk.build(self.dir, throwaway())

    def test_the_generator_registry_has_no_module_for_these_ids(self):
        import groups
        self.assertFalse([name for name in groups.REGISTRY if "prodk" in name])


class Scan(unittest.TestCase):
    """The scan is how a run says that nothing it wrote holds a scalar (the statement of destruction)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF

    def plant(self, data, name="f"):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_a_clean_tree_has_no_finding(self):
        self.plant(b"nothing here")
        self.assertEqual(prodk.scan([self.d], [self.root]), [])

    def test_every_form_a_scalar_could_be_written_in_is_found(self):
        raw = self.d.to_bytes(32, "big")
        forms = {
            "raw": raw,
            "lower-hex": b"%064x" % self.d,
            "upper-hex": ("%064X" % self.d).encode(),
            "base64url": base64.urlsafe_b64encode(raw).rstrip(b"="),
            "base64": base64.b64encode(raw),
            "decimal": str(self.d).encode(),
        }
        for label, form in forms.items():
            path = self.plant(b"prefix " + form + b" suffix", "case-" + label)
            self.assertEqual(prodk.scan([self.d], [self.root]), [path], label)
            path.unlink()

    def test_a_scalar_in_a_nested_directory_is_found(self):
        (self.root / "a" / "b").mkdir(parents=True)
        path = self.plant(b"%064x" % self.d, "a/b/deep")
        self.assertEqual(prodk.scan([self.d], [self.root]), [path])

    def test_a_missing_root_is_an_error_not_a_clean_result(self):
        with self.assertRaises(prodk.ProdkError):
            prodk.scan([self.d], [self.root / "nope"])

    def test_the_scan_counts_what_it_looked_at(self):
        self.plant(b"x", "one")
        self.plant(b"y", "two")
        self.assertEqual(prodk.files_scanned([self.root]), 2)


class Run(unittest.TestCase):
    """`run` is what the kit calls: build, check, scan, report, and the report holds public values only."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_the_report_names_the_public_keys_and_the_files_and_no_scalar(self):
        entries = throwaway()
        report = prodk.run(self.root / "stage", scan_roots=[self.root], entries=entries)
        self.assertEqual(sorted(report["kids"]), sorted(entries[n + ".sign"]["kid"] for n in prodk.PEOPLE))
        self.assertEqual(sorted(report["files"]), sorted(n.replace("/", ".") + ".json" for n in OWNER_IDS))
        for name, digest in report["files"].items():
            self.assertEqual(digest, hashlib.sha256((self.root / "stage" / name).read_bytes()).hexdigest())
        self.assertEqual(report["scalars_found"], [])
        self.assertGreater(report["files_scanned"], 0)
        self.assertEqual(report["production_profile"], base.production_profile())
        self.assertEqual(prodk.scan(prodk.scalars(entries), [self.root]), [])
        (self.root / "report.json").write_text(json.dumps(report))
        self.assertEqual(prodk.scan(prodk.scalars(entries), [self.root]), [])

    def test_a_scalar_left_in_a_scanned_root_is_reported_and_fails_the_run(self):
        entries = throwaway()
        leak = self.root / "leak.txt"
        leak.write_text("%064x" % int(entries["bob.sign"]["d"], 16))
        with self.assertRaises(prodk.ProdkError) as caught:
            prodk.run(self.root / "stage", scan_roots=[self.root], entries=entries)
        self.assertIn("leak.txt", str(caught.exception))

    def test_a_failed_check_leaves_no_vector_behind(self):
        class Refusing:
            def positive(self, *args):
                raise RuntimeError("vitni says no")

            def negative(self, *args):
                raise RuntimeError("vitni says no")
        with self.assertRaises(RuntimeError):
            prodk.run(self.root / "stage", scan_roots=[self.root], entries=throwaway(), crosscheck=Refusing())
        self.assertFalse((self.root / "stage").exists() and any((self.root / "stage").iterdir()))


class Command(unittest.TestCase):
    def test_both_vitni_binaries_are_required(self):
        import make_prodk
        self.assertEqual(make_prodk.main(["--out", "/nonexistent/x", "--evidence", "/nonexistent/e.json",
                                          "--scan-root", "/tmp"]), 2)

    def test_the_command_disables_core_dumps_before_it_draws_a_key(self):
        import make_prodk
        import resource
        before = resource.getrlimit(resource.RLIMIT_CORE)
        try:
            make_prodk.no_core_dumps()
            self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE)[0], 0)
        finally:
            resource.setrlimit(resource.RLIMIT_CORE, before)


if __name__ == "__main__":
    unittest.main()
