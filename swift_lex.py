"""Minimal Swift lexer for the architecture check.

Yields only CODE tokens with line numbers: comments (nested block comments included) and string-literal
text are dropped, but code inside string interpolations (`\\( ... )`) is kept, because
`"\\(UserDefaults.standard.string(forKey: k))"` is still a call to UserDefaults. The lexer treats candidate
source as data: it never imports, compiles or runs it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

IDENT_START = re.compile(r"[A-Za-z_@#$]")
IDENT_BODY = re.compile(r"[A-Za-z0-9_]")


@dataclass(frozen=True)
class Token:
    text: str
    line: int


def tokens(source: str) -> Iterator[Token]:
    i, n, line = 0, len(source), 1
    # Stack of string/interpolation contexts: ("str", hashes, multiline) or ("interp", paren_depth).
    stack: list[list] = []

    def peek(k: int = 0) -> str:
        return source[i + k] if i + k < n else ""

    while i < n:
        ch = source[i]
        if stack and stack[-1][0] == "str":
            _, hashes, multiline = stack[-1]
            closing = ('"""' if multiline else '"') + "#" * hashes
            if source.startswith(closing, i):
                i += len(closing)
                stack.pop()
                continue
            interp = "\\" + "#" * hashes + "("
            if source.startswith(interp, i):
                i += len(interp)
                stack.append(["interp", 1])
                continue
            if ch == "\\" and hashes == 0:
                if peek(1) == "\n":
                    line += 1
                i += 2
                continue
            if ch == "\n":
                line += 1
            i += 1
            continue
        # code context (top level or inside an interpolation)
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r":
            i += 1
            continue
        if source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
            continue
        if source.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if source[i] == "\n":
                        line += 1
                    i += 1
            continue
        # string literal openings: #*"""  or #*"
        m = re.match(r'(#*)(""")|(#*)(")', source[i:i + 16])
        if m and (m.group(2) or m.group(4)) and (ch == '"' or ch == "#"):
            if m.group(2):
                hashes, multiline, width = len(m.group(1)), True, len(m.group(1)) + 3
            else:
                hashes, multiline, width = len(m.group(3)), False, len(m.group(3)) + 1
            stack.append(["str", hashes, multiline])
            i += width
            continue
        if stack and stack[-1][0] == "interp":
            if ch == "(":
                stack[-1][1] += 1
            elif ch == ")":
                stack[-1][1] -= 1
                if stack[-1][1] == 0:
                    stack.pop()
                    i += 1
                    continue
        if IDENT_START.match(ch):
            j = i + 1
            while j < n and IDENT_BODY.match(source[j]):
                j += 1
            yield Token(source[i:j], line)
            i = j
            continue
        if ch.isdigit():
            j = i + 1
            while j < n and (source[j].isalnum() or source[j] in "._"):
                j += 1
            yield Token(source[i:j], line)
            i = j
            continue
        yield Token(ch, line)
        i += 1
