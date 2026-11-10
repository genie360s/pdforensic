"""Run the analyzer over any directory of PDFs you point it at.

    PDFORENSIC_CORPUS=/path/to/pdfs pytest tests/test_corpus.py

Several directories can be given, separated by the path separator (":" on
Linux and macOS, ";" on Windows). Skipped when the variable is not set.
Useful with your own documents and with openly licensed suites such as
https://github.com/bfocom/pdfa-testsuite (CC BY 3.0). Check a suite's terms
first: some, like the Ghent PDF Output Suite, restrict what they may be used for.
"""

import json
import os
import pathlib

import pikepdf
import pytest

from pdforensic import PdfError, analyze, format_report

ROOTS = [pathlib.Path(p) for p in os.environ.get("PDFORENSIC_CORPUS", "").split(os.pathsep) if p]


def _files():
    for root in ROOTS:
        for path in sorted(root.rglob("*")):
            if path.is_file() and "__MACOSX" not in path.parts and path.read_bytes()[:1024].find(b"%PDF-") >= 0:
                yield path


@pytest.mark.skipif(not ROOTS, reason="set PDFORENSIC_CORPUS to a directory of PDFs")
def test_corpus():
    checked = 0
    for path in _files():
        try:
            report = analyze(path)
        except PdfError:
            continue
        json.dumps(report)
        format_report(report)
        try:
            with pikepdf.open(path) as pdf:
                expected = len(pdf.pages)
        except Exception:  # noqa: BLE001 - qpdf cannot open it either (password, damage)
            expected = None
        if expected is not None:
            assert report["pages"]["count"] == expected, path
        checked += 1
    assert checked, "no PDF files found under PDFORENSIC_CORPUS"
