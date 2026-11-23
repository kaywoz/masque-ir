"""Compile many literal strings into one trie-shaped regex.

A plain alternation of N literals makes `re` try every branch at every
position; a trie-shaped pattern shares prefixes, so matching is roughly
O(text length x longest literal) instead of O(text length x N).
"""
from __future__ import annotations

import re


def _build(words: list[str]) -> dict:
    root: dict = {}
    for w in words:
        node = root
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = True
    return root


def _pattern(node: dict) -> str:
    end = "" in node
    branches = [re.escape(ch) + _pattern(child) for ch, child in sorted(node.items()) if ch != ""]
    if not branches:
        return ""
    if len(branches) == 1 and not end:
        return branches[0]
    body = "(?:" + "|".join(branches) + ")"
    return body + "?" if end else body


def compile_literals(words, flags: int = re.IGNORECASE) -> re.Pattern | None:
    """Regex matching any of `words` (longest first at each position), bounded
    so a match isn't part of a longer word. None when `words` is empty."""
    norm = sorted({w.casefold() if flags & re.IGNORECASE else w for w in words if w})
    if not norm:
        return None
    body = _pattern(_build(norm))
    return re.compile(r"(?<![\w.@-])(?:" + body + r")(?![\w@-]|\.\w)", flags)
