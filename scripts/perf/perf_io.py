"""Python 3.9-compatible deterministic filesystem writers for perf evidence."""

from __future__ import annotations

import pathlib


def write_text_lf(path: pathlib.Path, text: str) -> None:
    """Write UTF-8 text with LF newlines on every supported platform."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def atomic_write_text_lf(path: pathlib.Path, text: str) -> None:
    """Atomically replace ``path`` with deterministic UTF-8/LF text."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    write_text_lf(temporary, text)
    temporary.replace(path)
