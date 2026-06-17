"""JSONC parsing — JSON with comments and trailing commas.

Supports ``//`` line comments, ``/* ... */`` block comments, and trailing
commas before ``}``/``]``. Comment markers and commas inside string literals
are preserved verbatim (a naive regex would corrupt values like
``"mongodb://host"`` or ``"/* literal */"``).

Every JSON config file Locke reads is parsed tolerantly, so authors may
annotate plaintext configs *and* the checked-in encrypted files with comments.
The encrypted payload itself is always written as plain JSON; the decrypted
plaintext is parsed strictly, since it is machine-generated and never authored
by hand.
"""

import json
from typing import IO, Any

__all__ = ["load_jsonc", "parse_jsonc", "strip_jsonc"]


def parse_jsonc(text: str) -> Any:
    """Parse JSONC text into a Python object."""
    return json.loads(strip_jsonc(text))


def load_jsonc(fp: IO[str]) -> Any:
    """Read and parse JSONC from an open text file object.

    Drop-in replacement for :func:`json.load` that tolerates comments and
    trailing commas. Raises :class:`json.JSONDecodeError` on malformed input.
    """
    return parse_jsonc(fp.read())


def strip_jsonc(text: str) -> str:
    """Return ``text`` with comments and trailing commas removed.

    The result is valid JSON parseable by :func:`json.loads`.
    """
    return _strip_trailing_commas(_strip_comments(text))


def _strip_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2  # consume the closing */
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # drop the trailing comma
                continue
        out.append(ch)
        i += 1
    return "".join(out)
