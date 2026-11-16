"""T15.10: the scripts that ship in the repo use only tools the CI runner and any contributor's machine have.

The maintainer's own shell has replacements for grep, find, sed and cat (rg, fd, sd, bat, eza). Those are the
maintainer's tools: they govern a person's interactive commands, never code that is committed. A script that calls one
passes on the maintainer's Mac and fails on the runner (`sd: not found`), so no script, test script or workflow may
call them. Text checks only (the repo tools use the standard library).
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PERSONAL = ("sd", "rg", "fd", "bat", "eza")
# a command word: at the start of a line, after ; & | ( { ` ! or $(, or after a shell keyword
COMMAND = re.compile(r"(?:^|[;&|({`!]|\$\(|\b(?:if|then|else|elif|do|while|until)\b)\s*(%s)(?=\s|$)" % "|".join(PERSONAL))
SHELL_DIRS = ("tools", "signer", "checker", "conformance", "spec", ".github")


def scripts():
    found = []
    for name in SHELL_DIRS:
        base = ROOT / name
        if base.is_dir():
            for path in base.rglob("*"):
                parts = set(path.relative_to(ROOT).parts)
                if parts & {".git", ".build", "target", ".venv", "node_modules", "__pycache__"}:
                    continue
                if path.is_file() and path.suffix in (".sh", ".yml", ".yaml"):
                    found.append(path)
    return sorted(found)


def offending_lines(path):
    hits = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = COMMAND.search(line)
        if match:
            hits.append("%s:%d: calls %s: %s" % (path.relative_to(ROOT), number, match.group(1), line.strip()))
    return hits


class PersonalTools(unittest.TestCase):
    def test_there_are_scripts_to_check(self):
        names = {p.name for p in scripts()}
        self.assertIn("build-vitni.sh", names)
        self.assertIn("linux-server.yml", names)

    def test_no_shipped_script_or_workflow_calls_a_personal_tool(self):
        hits = [hit for path in scripts() for hit in offending_lines(path)]
        self.assertEqual(hits, [])

    def test_the_scanner_sees_the_forms_it_exists_for(self):
        for line in ("sd -F a b file", "  rg -q x y", "x=$(fd . dir)", "a | bat -p f", "cd d && eza", "if rg -q x; then", "`sd a b`"):
            with self.subTest(line=line):
                self.assertIsNotNone(COMMAND.search(line))
        for line in ("# sd -F a b", "printf 'use rg here'", "grep -q sd file", "bash -c sdx", "echo hidden fd"):
            with self.subTest(line=line):
                if line.startswith("#"):
                    continue
                self.assertIsNone(COMMAND.search(line))


if __name__ == "__main__":
    unittest.main()
