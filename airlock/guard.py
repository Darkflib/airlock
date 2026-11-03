"""Context guard: screens untrusted text (package files, tool output) before it
reaches the agent, redacting likely prompt injection.

Pattern-based for now. The content-safety model scores "user safety", not
injection, so it is not wired in until the guard eval shows it adds anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

REDACTED = "[airlock: redacted suspected prompt injection]"

_AUDIENCE = r"(?:ai|llm|gpt|claude|assistant|agent|model|bot|(?:code\s+)?reviewers?|automated\s+review\w*)"
_ASK = (
    r"(?:approve|approved|mark\s+(?:it|this|the\s+package)\s+(?:as\s+)?(?:safe|approved|benign)|"
    r"(?:is|are)\s+(?:safe|benign|trusted)|skip\s+(?:review|analysis|checks?)|do\s+not\s+flag|"
    r"report\s+(?:it\s+)?as\s+(?:safe|benign))"
)
PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)", re.I),
    re.compile(rf"\b{_AUDIENCE}\b[^\n]{{0,120}}?\b{_ASK}\b[^\n]*", re.I),
    re.compile(r"\b(?:system\s+prompt|you\s+are\s+now|new\s+instructions?)\s*[:\-][^\n]*", re.I),
]


@dataclass
class Finding:
    pattern: int
    text: str


def screen(text: str) -> tuple[str, list[Finding]]:
    """Return (redacted_text, findings). Redacts whole matched spans."""
    findings: list[Finding] = []

    def sub(i: int):
        def repl(m: re.Match) -> str:
            findings.append(Finding(pattern=i, text=m.group(0)[:200]))
            return REDACTED
        return repl

    for i, pat in enumerate(PATTERNS):
        text = pat.sub(sub(i), text)
    return text, findings
