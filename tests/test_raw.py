"""Unit tests for the raw byte-level layer (pdforensic/_pdf.py)."""

import pdfgen
import pytest
from conftest import FIXTURES

from pdforensic._pdf import Name, Parser, PdfError, RawPdf, Ref, Stream, parse_indirect


def parse(text):
    return Parser(text).parse()


@pytest.mark.parametrize("text, expected", [
    (b"42", 42), (b"-17", -17), (b"+3", 3), (b"3.5", 3.5), (b"-.25", -0.25), (b"4.", 4.0),
    (b"true", True), (b"false", False), (b"null", None),
    (b"12 0 R", Ref(12, 0)), (b"[1 2 R 3]", [Ref(1, 2), 3]),
    (b"/Name", Name("Name")), (b"/A#20B", Name("A B")), (b"/J#61vaScript", Name("JavaScript")),
    (b"(plain)", b"plain"), (b"(a(b)c)", b"a(b)c"), (b"(\\(\\)\\\\)", b"()\\"),
    (b"(\\101\\7\\n)", b"A\x07\n"), (b"(one\\\ntwo)", b"onetwo"), (b"(a\r\nb)", b"a\nb"),
    (b"<48656C6C6F>", b"Hello"), (b"<48 65 6C 6C 6F>", b"Hello"), (b"<4>", b"@"),
    (b"<< /A 1 /B [2 3] /C << /D (x) >> >>", {"A": 1, "B": [2, 3], "C": {"D": b"x"}}),
    (b"% comment\n 7", 7),
])
def test_parse_objects(text, expected):
    assert parse(text) == expected


@pytest.mark.parametrize("text", [b"(unterminated", b"<zz>", b"<< /A >>", b"<< 1 2 >>", b"[1 2", b"wat", b"", b"[" * 500])
def test_parse_rejects_malformed(text):
    with pytest.raises(PdfError):
        parse(text)


def test_reference_is_not_confused_with_numbers():
    assert parse(b"[1 0 2]") == [1, 0, 2]
    assert parse(b"[1 0 R 2]") == [Ref(1, 0), 2]


def test_parse_indirect_stream_uses_length():
    data = b"5 0 obj\n<< /Length 9 >>\nstream\nendstream\nendstream\nendobj\n"
    num, gen, value, end = parse_indirect(data, 0)
    assert (num, gen) == (5, 0) and isinstance(value, Stream)
    assert data[value.start:value.end] == b"endstream"  # data that looks like the keyword
    assert end == len(data) - 1


def test_parse_indirect_falls_back_when_length_is_wrong():
    data = b"5 0 obj\n<< /Length 999 >>\nstream\nabc\nendstream\nendobj\n"
    value = parse_indirect(data, 0)[2]
    assert data[value.start:value.end] == b"abc"


def test_not_a_pdf():
    with pytest.raises(PdfError, match="not a PDF"):
        RawPdf(b"PK\x03\x04 this is a zip file")


def test_header_and_object_index():
    raw = RawPdf(pdfgen.simple())
    assert raw.version == "1.4" and raw.header_offset == 0
    assert raw.header_ids == [(n, 0) for n in range(1, 7)]
    assert all(raw.data[h:].startswith(b"%d 0 obj" % n) for h, (n, _) in zip(raw.headers, raw.header_ids))
    assert raw.header_before(raw.headers[2] + 5) == (raw.headers[2], (3, 0))


def test_bytes_before_header_are_reported():
    raw = RawPdf(b"junk\n" + pdfgen.simple())
    assert raw.header_offset == 5 and "precede" in raw.warnings[0]


@pytest.mark.parametrize("builder, count, kinds", [
    (pdfgen.simple, 1, ["table"]),
    (pdfgen.updated, 2, ["table", "table"]),
    (pdfgen.deleted, 3, ["table", "table", "table"]),
    (pdfgen.xref_stream, 1, ["stream"]),
])
def test_revisions(builder, count, kinds):
    data = builder()
    raw = RawPdf(data)
    revisions = raw.build_revisions()
    assert len(revisions) == count and [r.kind for r in revisions] == kinds
    assert revisions[0].start == 0 and revisions[-1].end == len(data)
    assert all(a.end == b.start for a, b in zip(revisions, revisions[1:]))
    assert all(data[: r.end].rstrip().endswith(b"%%EOF") for r in revisions)
    assert raw.warnings == [] and raw.trailing_bytes == 0


def test_update_trailer_points_back_to_previous_section():
    raw = RawPdf(pdfgen.updated())
    first, second = raw.build_revisions()
    assert first.prev is None and second.prev == first.startxref
    assert second.trailer["ID"][0] == first.trailer["ID"][0] != second.trailer["ID"][1]


def test_linearized_file_is_one_revision():
    """ISO 32000-1 7.5.4: a linearized file has two cross-reference sections
    (and two %%EOF markers) without ever having been updated."""
    raw = RawPdf((FIXTURES / "qpdf_linearized.pdf").read_bytes())
    assert raw.eof_markers == 2
    assert len(raw.build_revisions()) == 1
    assert raw.linearized is not None and raw.linearized_intact is True


def test_linearization_length_must_match_a_boundary():
    """A bogus /L must not be allowed to hide later revisions."""
    data = pdfgen.updated().replace(b"1 0 obj\n<< /Type /Catalog", b"1 0 obj\n<< /Linearized 1 /L 999999 /Type /Catalog", 1)
    raw = RawPdf(data)
    assert len(raw.build_revisions()) == 2
    assert any("not treated as linearized" in w for w in raw.warnings)


def test_wrong_startxref_is_reported():
    data = pdfgen.simple().replace(b"startxref\n", b"startxref\n9")
    raw = RawPdf(data)
    (rev,) = raw.build_revisions()
    assert rev.error and "does not point to a cross-reference section" in rev.error


def test_truncated_file_without_trailer():
    data = pdfgen.simple()
    raw = RawPdf(data[: data.index(b"xref")])
    (rev,) = raw.build_revisions()
    assert rev.error and any("truncated" in w for w in raw.warnings)


def test_trailing_bytes():
    raw = RawPdf(pdfgen.simple() + b"<script>hidden payload</script>")
    raw.build_revisions()
    assert raw.trailing_bytes == 31
