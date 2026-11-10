"""Robustness: corrupted and hostile files must never crash the analyzer.

Each input is a fixture damaged at random (truncated, bytes flipped, chunks
moved, structural keywords injected). The only acceptable outcomes are a
report or PdfError ("not a PDF").
"""

import json
import random

import pdfgen
import pytest
from conftest import FIXTURES, NOW

from pdforensic import PdfError, analyze, format_report, recover_revisions

TOKENS = [b"startxref\n0\n%%EOF\n", b"%%EOF", b" 0 obj\n", b"endobj", b"stream\n", b"endstream", b"xref\n0 1\n",
          b"trailer\n<<", b">>", b"/Prev 99999999", b"/XRefStm 0", b"/Linearized 1 /L 5", b"/ByteRange [0 1 2 3]",
          b"/Length -1", b"/Length 99999999999", b"[" * 400, b"<<" * 400, b"(" * 300, b"/Encrypt 1 0 R",
          b"\x00" * 50, b"9" * 5000, b"/A#ff#fe (x)", b"(D:20240101000000+99'99')"]


def seeds():
    builders = ("simple", "updated", "deleted", "xref_stream", "hybrid", "image_only", "with_xmp", "signed",
                "unsigned", "embedded_pdf", "javascript")
    return [getattr(pdfgen, name)() for name in builders] + [p.read_bytes() for p in sorted(FIXTURES.glob("*.pdf"))]


def mutate(rng, data, pool):
    if len(data) < 2:
        return data + rng.choice(TOKENS)
    d, kind = bytearray(data), rng.randrange(8)
    if kind == 0:
        return bytes(d[: rng.randrange(len(d) + 1)])
    if kind == 1:
        for _ in range(rng.randrange(1, 12)):
            d[rng.randrange(len(d))] = rng.randrange(256)
    elif kind == 2:
        a = rng.randrange(len(d))
        del d[a : a + rng.randrange(1, 200)]
    elif kind == 3:
        a, b = rng.randrange(len(d)), rng.randrange(len(d))
        d[a:a] = d[b : b + rng.randrange(1, 300)]
    elif kind in (4, 5):
        for _ in range(1 if kind == 4 else rng.randrange(1, 6)):
            a = rng.randrange(len(d))
            d[a:a] = rng.choice(TOKENS)
    elif kind == 6:  # scrambled digits hit offsets, lengths and object numbers
        digits = [i for i, c in enumerate(d) if 48 <= c <= 57]
        for i in rng.sample(digits, min(len(digits), rng.randrange(1, 10))):
            d[i] = rng.randrange(48, 58)
    else:
        d += rng.choice(pool)[rng.randrange(200) :]
    return bytes(d)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_damaged_files_never_crash(seed, tmp_path):
    rng, pool = random.Random(seed), seeds()
    for i in range(400):
        data = mutate(rng, rng.choice(pool), pool)
        if rng.random() < 0.3:
            data = mutate(rng, data, pool)
        try:
            report = analyze(data, now=NOW)
        except PdfError:
            continue
        json.dumps(report)
        format_report(report)
        if i % 20 == 0:
            recover_revisions(data, tmp_path)


def test_names_that_are_not_utf8(tmp_path):
    """Regression: a key with undecodable bytes cannot be handed back to qpdf."""
    data = pdfgen.simple().replace(b"/Title (Fixture)", b"/T#ff#fe (Fixture)")
    report = analyze(data, now=NOW)
    assert report["info"]["Producer"] == "pdfgen 1.0" and len(report["info"]) == 5
    json.dumps(report)


def test_absurd_timezone_offset():
    data = pdfgen.simple(created="D:20240102030405+99'99'", modified="D:20240102030405+99'99'")
    report = analyze(data, now=NOW)
    assert report["info_dates"] == {"CreationDate": None, "ModDate": None}


def test_oversized_numbers_in_a_byte_range():
    """Regression: Python refuses to convert digit runs longer than 4300 characters."""
    data = pdfgen.simple() + b"\n7 0 obj\n<< /ByteRange [0 1 2 " + b"9" * 5000 + b"] /Contents <00> >>\nendobj\n"
    report = analyze(data, now=NOW)
    assert report["structure"]["revision_count"] == 1
