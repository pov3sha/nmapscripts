#!/usr/bin/env python3
"""Builds BLOG.md from BLOG.template.md.

Replaces each {{FILE:path}} marker with the contents of that file (scripts and
real captured outputs). If an output file does not exist yet, a clear marker is
left in its place and a warning is printed. Nothing is invented.
Run from the project root:  python3 tests/build_blog.py
"""
import pathlib
import re

root = pathlib.Path(__file__).resolve().parent.parent
template = (root / "BLOG.template.md").read_text()
missing = []


def fill(match):
    rel = match.group(1)
    path = root / rel
    if path.exists():
        return path.read_text().rstrip("\n")
    missing.append(rel)
    return f"[OUTPUT NOT YET GENERATED: run tests/run_blog_tests.sh to create {rel}]"


(root / "BLOG.md").write_text(re.sub(r"\{\{FILE:([^}]+)\}\}", fill, template))
print("Wrote BLOG.md")
for rel in missing:
    print("WARNING: missing", rel)
