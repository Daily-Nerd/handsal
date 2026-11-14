"""Regenerate conformance/fixtures/agree-kat.json (the known answers of `agree`, SG-16).

Run: uv run python -I conformance/vectors/_gen/make_agree_kat.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib import agree  # noqa: E402

if __name__ == "__main__":
    agree.write(HERE.parents[1] / "fixtures")
