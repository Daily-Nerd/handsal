"""Cross-checks spec/registry.json against the tables and sentences of
the profile. The prose and the registry describe the same facts, so
this test is the guard: a fact present on one side and missing or different
on the other is a failure, in both directions."""

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "spec" / "registry.json"
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402

# Registry-side tokens for the prose cells of the hash columns of ACT-09.
INPUT_CELLS = {
    "EMPTY_HASH": "empty",
    "hashstr(JCS(genesis document))": "jcs_genesis_document",
    "hashstr(raw request bytes)": "raw_request_bytes",
    "hashstr(raw record body bytes)": "raw_record_body_bytes",
}
OUTPUT_CELLS = {
    "EMPTY_HASH": "empty",
    'hashstr(JCS({"request_id":R,"verdict":"approve"}))': "verdict:approve",
    "verdict `reject`": "verdict:reject",
    "verdict `needs-info`": "verdict:needs-info",
}
HEAD_CELLS = {"never": "never", "always": "always"}
# Registry type -> the words the Field types paragraph must use for the key.
TYPE_PROSE = {
    "b64u32": "base64url of 32 bytes",
    "class_id": "registry id",
    "kid": "43-character thumbprint",
    "member_id": "`member_id`",
    "role_id": "`role_id`",
    "hostname": "`hostname`",
    "request_id": "`request_id`",
    "record_id": "`record_id`",
    "label": "`label`",
}


def profile_text():
    return manifest.read_profile(ROOT)


def load():
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def section(text, heading_re):
    """Text from the heading matching heading_re up to the next heading."""
    m = re.search(r"^#{2,4} " + heading_re + r".*$", text, re.M)
    assert m, "heading not found: " + heading_re
    rest = text[m.end():]
    n = re.search(r"^#{2,4} ", rest, re.M)
    return rest[:n.start()] if n else rest


def table_rows(block):
    """Rows of the first pipe table in block, header and rule dropped."""
    rows = []
    for line in block.splitlines():
        if line.startswith("|"):
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
        elif rows:
            break
    return rows[2:]


def split_top(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_keys(s):
    """'{a, b:{c,d}}' -> {'a': None, 'b': {'c': None, 'd': None}}."""
    s = s.strip()
    assert s[0] == "{" and s[-1] == "}", s
    tree = {}
    for item in split_top(s[1:-1]):
        name, _, rest = item.partition(":")
        tree[name.strip()] = parse_keys(rest) if rest.strip() else None
    return tree


def reg_tree(node):
    if "keys" in node:
        return {k: reg_tree(v) for k, v in node["keys"].items()}
    return None


def body_cell_tree(cell):
    cell = re.sub(r"\s*\([^)]*\)\s*$", "", cell.strip())
    return parse_keys(cell.strip("`"))


def flatten(v):
    if isinstance(v, dict):
        for k, x in v.items():
            if k != "unit":
                yield from flatten(x)
    else:
        yield v


def norm(name):
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower()


class KeyClasses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = load()
        cls.kc01 = section(profile_text(), r"KC-01")

    def prose_rows(self):
        rows = []
        for r in table_rows(self.kc01):
            uv = re.fullmatch(r"`(\w+)`", r[4])
            rows.append({
                "id": r[0].strip("`"), "alg": r[1],
                "hardware_bound": r[2] == "true",
                "per_signature_user_verification": r[3] == "true",
                "user_verification": uv.group(1) if uv else None,
                "status": re.match(r"`([\w-]+)`", r[5]).group(1),
            })
        return rows

    def test_classes_match_the_kc01_table(self):
        self.assertEqual(self.reg["key_classes"], self.prose_rows())

    def test_a_tagged_registry_holds_no_pending_class(self):
        """KC-02: the first tag is macOS only, so `win-hello-hw` is not in the registry (T7.7). The
        `pending-spike` status stays in the enum for the Windows tag."""
        self.assertEqual([c["id"] for c in self.reg["key_classes"]], ["apple-se-bio", "test-sw-p256"])
        self.assertIn("pending-spike", self.reg["enums"]["status"])
        for c in self.reg["key_classes"]:
            self.assertNotEqual(c["status"], "pending-spike", c["id"])
            self.assertIn(c["user_verification"], self.reg["enums"]["user_verification"])

    def test_fixture_only_matches_the_sentence(self):
        m = re.search(
            r"Version 1 lists one entry: `([\w-]+)` \((\w+), `hardware_bound` (\w+), "
            r"`per_signature_user_verification` (\w+), `user_verification` `(\w+)`, "
            r"`status` `(\w+)`\)", self.kc01)
        self.assertTrue(m, "fixture_only sentence not found")
        want = {"id": m.group(1), "alg": m.group(2),
                "hardware_bound": m.group(3) == "true",
                "per_signature_user_verification": m.group(4) == "true",
                "user_verification": m.group(5), "status": m.group(6)}
        self.assertEqual(self.reg["fixture_only"], [want])

    def test_enums_match_the_sentence(self):
        s = self.kc01
        uv = re.search(r"`user_verification` \(([^)]*)\)", s).group(1)
        st = re.search(r"`status` \(([^)]*)\)", s).group(1)
        names = lambda x: re.findall(r"`([\w-]+)`", x)
        self.assertEqual(self.reg["enums"]["user_verification"], names(uv))
        self.assertEqual(self.reg["enums"]["status"], names(st))
        self.assertEqual(self.reg["enums"]["alg"], ["ES256"])
        for c in self.reg["key_classes"] + self.reg["fixture_only"]:
            self.assertIn(c["alg"], self.reg["enums"]["alg"])
            self.assertIn(c["status"], self.reg["enums"]["status"])

    def test_class_ids_are_unique_and_fixture_ids_are_not_production(self):
        prod = [c["id"] for c in self.reg["key_classes"]]
        fix = [c["id"] for c in self.reg["fixture_only"]]
        self.assertEqual(len(prod), len(set(prod)))
        self.assertEqual(set(prod) & set(fix), set())


class Methods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = load()
        cls.text = profile_text()
        cls.act09 = section(cls.text, r"ACT-09")
        cls.rows = table_rows(cls.act09)
        cls.by_name = {m["method"]: m for m in cls.reg["methods"]}

    def test_method_names_match_in_both_directions(self):
        prose = [r[0].strip("`") for r in self.rows]
        self.assertEqual([m["method"] for m in self.reg["methods"]], prose)
        self.assertEqual(len(prose), 10)
        self.assertIn("local:handsal.record.promote", self.by_name)
        self.assertNotIn("local:handsal.relay.tip", self.by_name)
        self.assertNotIn("local:handsal.request.send", self.by_name)

    def test_binding_is_local(self):
        self.assertEqual(self.reg["binding"], "local")
        self.assertIn('all with `binding="local"`', self.act09)

    def test_extra_keys_head_and_hash_columns(self):
        approve = None
        for r in self.rows:
            name = r[0].strip("`")
            m = self.by_name[name]
            if r[1] == "none":
                extra = []
            elif r[1] == "same":
                extra = approve
            else:
                extra = re.findall(r"`(\w+)`", r[1])
            if name.endswith("request.approve"):
                approve = extra
            self.assertEqual(m["act_extra_keys"], extra, name)
            head = "conditional" if r[2].startswith("present iff") else HEAD_CELLS[r[2]]
            self.assertEqual(m["head"], head, name)
            self.assertEqual(m["inputs_hash"], INPUT_CELLS.get(r[4], r[4]) if r[4] != "same" else self.by_name["local:handsal.request.approve"]["inputs_hash"], name)
            self.assertIn(r[4], list(INPUT_CELLS) + ["same"], name)
            self.assertIn(r[5], OUTPUT_CELLS, name)
            self.assertEqual(m["outputs_hash"], OUTPUT_CELLS[r[5]], name)

    def test_bodies_match_the_closed_schema_column(self):
        for r in self.rows:
            name = r[0].strip("`")
            self.assertEqual(reg_tree(self.by_name[name]["body"]), body_cell_tree(r[3]), name)

    def test_leaf_types_agree_with_the_field_types_paragraph(self):
        para = re.search(r"^Field types: (.*)$", self.act09, re.M).group(1)
        clauses = {}
        for clause in re.split(r"; |\. ", para):
            m = re.match(r"((?:`\w+`(?:, | and )?)+) (?:is|are) (.*)", clause)
            if m:
                for n in re.findall(r"`(\w+)`", m.group(1)):
                    clauses[n] = m.group(2)

        def leaves(node, name):
            if "keys" in node:
                for k, v in node["keys"].items():
                    yield from leaves(v, k)
            elif node["type"] == "list":
                of = node["of"]
                if isinstance(of, dict):
                    yield from leaves(of, name)
                else:
                    yield name, of
            else:
                yield name, node["type"]

        seen = 0
        for m in self.reg["methods"]:
            pairs = list(leaves(m["body"], ""))
            pairs += list(m["act_extra_keys"] and
                          [(k, self.reg["act_extra_key_types"][k]) for k in m["act_extra_keys"]])
            for key, typ in pairs:
                want = TYPE_PROSE.get(typ) or ("`anchor`" if typ == "anchor" else None)
                if want is None:
                    continue
                self.assertIn(key, clauses, "%s.%s" % (m["method"], key))
                self.assertIn(want, clauses[key], "%s.%s" % (m["method"], key))
                seen += 1
        self.assertGreater(seen, 15)

    def test_extra_key_types_cover_exactly_the_extra_keys(self):
        used = {k for m in self.reg["methods"] for k in m["act_extra_keys"]}
        self.assertEqual(set(self.reg["act_extra_key_types"]), used)
        self.assertIn("`ts` and `expires` MUST be `time`", self.text)

    def test_list_caps_resolve_to_constants_and_match_prose(self):
        consts = self.reg["constants"]

        def walk(node):
            if "keys" in node:
                for v in node["keys"].values():
                    yield from walk(v)
            elif node["type"] == "list":
                if "cap" in node:
                    yield node["cap"]
                if isinstance(node["of"], dict):
                    yield from walk(node["of"])

        caps = [c for m in self.reg["methods"] for c in walk(m["body"])]
        self.assertEqual(sorted(caps), sorted([
            "chain_resolve_caps.candidates", "chain_resolve_caps.heads",
            "chain_resolve_caps.overrides", "chain_resolve_caps.endorsements_per_override",
            "record_promote_anchors"]))
        for c in caps:
            cur = consts
            for part in c.split("."):
                cur = cur[part]
            self.assertEqual(set(cur), {"min", "max"}, c)
        c = consts["chain_resolve_caps"]
        want = ("- `candidates`: %s to %s distinct" % (c["candidates"]["min"], c["candidates"]["max"]),
                "- `heads`: %s to %s distinct" % (c["heads"]["min"], c["heads"]["max"]),
                "- `overrides`: %s to %s entries" % (c["overrides"]["min"], c["overrides"]["max"]),
                "`endorsements` %s to %s distinct" % (c["endorsements_per_override"]["min"], c["endorsements_per_override"]["max"]),
                "`anchors` is a list of %s to %s" % (consts["record_promote_anchors"]["min"], consts["record_promote_anchors"]["max"]))
        for w in want:
            self.assertIn(w, self.act09)


class Constants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = load()
        cls.rows = table_rows(section(profile_text(), r"2\.3"))

    def prose_numbers(self, cell):
        cell = re.sub(r"\([^)]*\)", "", cell)
        return re.findall(r"\d+", cell)

    def test_every_table_row_is_in_the_registry_and_back(self):
        prose_names = []
        for r in self.rows:
            names = [norm(n) for n in re.findall(r"`([^`]+)`", r[0])] if r[0].startswith("`") and "," in r[0] else [norm(re.sub(r"`", "", r[0]))]
            prose_names += names
            for n in names:
                self.assertIn(n, {norm(k) for k in self.reg["constants"]}, n)
        self.assertEqual(sorted(prose_names), sorted(norm(k) for k in self.reg["constants"]))

    def test_numbers_agree_row_by_row(self):
        by = {norm(k): v for k, v in self.reg["constants"].items()}
        for r in self.rows:
            if r[0].startswith("`") and "," in r[0]:
                names = [norm(n) for n in re.findall(r"`([^`]+)`", r[0])]
            else:
                names = [norm(re.sub(r"`", "", r[0]))]
            for n in names:
                self.assertEqual(list(flatten(by[n])), self.prose_numbers(r[1]), n)

    def test_the_four_core_constants_are_named_as_in_the_prose(self):
        for n in ("MAX_PAYLOAD", "MAX_DEPTH", "MAX_INPUT", "MAX_EXPIRES_IN_S"):
            self.assertIn(n, self.reg["constants"])

    def test_values_are_decimal_strings(self):
        for v in flatten(self.reg["constants"]):
            self.assertIsInstance(v, str)
            self.assertRegex(v, r"^(0|[1-9][0-9]{0,8})$")


class Shape(unittest.TestCase):
    def test_no_json_number_anywhere(self):
        def walk(v):
            if isinstance(v, dict):
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
            else:
                self.assertFalse(isinstance(v, (int, float)) and not isinstance(v, bool), v)
        walk(load())

    def test_file_is_utf8_ascii_with_final_newline(self):
        raw = REGISTRY.read_bytes()
        raw.decode("ascii")
        self.assertTrue(raw.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
