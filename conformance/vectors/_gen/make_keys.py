"""Regenerate conformance/fixtures/keys.json and fixture-kids.json.

Run: uv run python -I conformance/vectors/_gen/make_keys.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib import keys  # noqa: E402

if __name__ == "__main__":
    keys.write(HERE.parents[1] / "fixtures")
