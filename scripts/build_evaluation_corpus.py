#!/usr/bin/env python3
"""Offline reproduction/check of the pinned third-party evaluation corpus."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prufgate.evaluation_corpus import build
from prufgate.safe_fs import safe_write_text

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--write', action='store_true', help='Write the reproducible cases locally')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1] / 'bench' / 'testdata' / 'independent'
outputs = build(root)
if args.write:
    for name, text in outputs.items():
        safe_write_text(root / name, text, encoding='utf-8')
else:
    if set(outputs) != {p.name for p in root.glob('*.txt')} or any((root / name).read_text() != text for name, text in outputs.items()):
        parser.exit(2, 'Corpus differs from frozen upstream derivation.\n')
print(f'{len(outputs)} upstream-derived cases verified; no source code executed.')
