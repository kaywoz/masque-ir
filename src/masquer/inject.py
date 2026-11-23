"""Instruction-like text in exported data (prompt injection aimed at the
analysing model). Counted for the outbox header; optionally replaced by
tokens (restored in the report) for assistants that refuse such input.

Patterns are phrase-level and conservative: false positives only add a
header note or a token, never drop data.
"""
from __future__ import annotations

import re

_PHRASES = [
    r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)",
    r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+\w+",
    r"forget\s+(?:all\s+|everything\s+)?(?:you|your)\s+(?:were\s+told|instructions)",
    r"(?:reveal|print|show|output|dump|list)\s+(?:me\s+)?(?:all\s+|every\s+)?(?:the\s+)?(?:original|unredacted|real|raw|hidden)\s+\w+",
    r"(?:reveal|print|show|output|dump)\s+(?:the\s+)?(?:token\s+)?(?:mapping|deny-?list|system\s+prompt)",
    r"you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted)\b",
    r"</?\s*(?:data|system|instructions?|prompt)\s*>",
    r"(?:^|[\s\"'])(?:system|assistant)\s*:\s*\w+",
    r"do\s+anything\s+now",
]
INJECTION_RE = re.compile(
    r"(?is)(?:" + "|".join(_PHRASES) + r")[^\n\"'|\t]{0,160}",
)


def count_rows(block: str) -> int:
    """Lines of a rendered table block that contain instruction-like text."""
    return sum(1 for line in block.splitlines() if INJECTION_RE.search(line))
