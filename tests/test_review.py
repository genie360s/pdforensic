"""Regression tests for defects found in code review. Each test builds the
smallest file that showed the defect."""

import tracemalloc
import zlib

import pdfgen
import pytest
from conftest import NOW

from pdforensic import analyze
from pdforensic.forensics import parse_xmp


def run(data):
    return analyze(data, now=NOW)


def found(report):
    return {i["id"]: i["severity"] for i in report["tamper"]["indicators"]}


# ---- an update after signing must not be excused by a token object ----------------

def test_dummy_dss_object_does_not_excuse_other_changes():
    b = pdfgen.Builder.resume(pdfgen.signed())
    b.stream(4, b"", pdfgen.CONTENT.replace(b"Hello", b"Altered"))
    b.obj(9, b"<< /Type /DSS >>")
    r = run(b.finish(pdfgen.trailer(id1=pdfgen.ID_B)).bytes())
    assert found(r)["content_after_signature"] == "high" and found(r)["incremental_updates"] == "medium"
    assert r["revisions"][1]["signing"] is False


def test_update_that_only_adds_validation_data_is_still_recognised():
    b = pdfgen.Builder.resume(pdfgen.signed())
    b.stream(10, b"", b"certificate bytes")
    b.obj(9, b"<< /Type /DSS /Certs [10 0 R] >>")
    b.obj(1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [8 0 R] /SigFlags 3 >> /DSS 9 0 R >>")
    r = run(b.finish(pdfgen.trailer(id1=pdfgen.ID_B)).bytes())
    assert r["revisions"][1]["signing"] is True
    assert found(r)["content_after_signature"] == "info" and found(r)["incremental_updates"] == "info"


def test_validation_update_may_refresh_the_documents_metadata():
    """Seen in real long-term-validation updates: Info and XMP are rewritten too."""
    b = pdfgen.Builder.resume(pdfgen.signed(xmp_extra=b""))
    b.stream(11, b"", b"certificate bytes")
    b.obj(10, b"<< /Type /DSS /Certs [11 0 R] >>")
    b.obj(6, pdfgen.info(modified="D:20240102030500+00'00'"))
    b.stream(9, b"/Type /Metadata /Subtype /XML",
             pdfgen.XMP % {b"producer": b"pdfgen 1.0", b"modified": b"2024-01-02T03:05:00Z", b"extra": b""})
    b.obj(1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [8 0 R] /SigFlags 3 >> /Metadata 9 0 R /DSS 10 0 R >>")
    r = run(b.finish(pdfgen.trailer(id1=pdfgen.ID_B)).bytes())
    assert {c["type"] for c in r["revisions"][1]["changes"]} == {"Catalog", "DSS", "Info", "Metadata/XML", "Stream"}
    assert r["revisions"][1]["signing"] is True and found(r)["content_after_signature"] == "info"


def test_later_signature_lowers_the_finding_but_does_not_clear_it():
    """A second signature seals what its revision changed, yet nothing here
    verifies it, so a made-up signature dictionary must not excuse an edit."""
    first = pdfgen.signed()
    b = pdfgen.Builder.resume(first)
    b.stream(4, b"", pdfgen.CONTENT.replace(b"Hello", b"Altered"))
    placeholder = b"/ByteRange [0000000000 0000000000 0000000000 0000000000]"
    b.obj(9, b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Name (Second) "
             + placeholder + b" /Contents <" + b"00" * 64 + b"> >>")
    b.obj(10, b"<< /FT /Sig /T (Signature2) /V 9 0 R /Type /Annot /Subtype /Widget /Rect [0 0 0 0] >>")
    b.obj(1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [8 0 R 10 0 R] /SigFlags 3 >> >>")
    b.finish(pdfgen.trailer(id1=pdfgen.ID_B))
    start = b.buf.index(b"/Contents <", b.buf.index(b"9 0 obj")) + len(b"/Contents ")
    end = b.buf.index(b">", start) + 1
    at = b.buf.index(placeholder)
    b.buf[at : at + len(placeholder)] = b"/ByteRange [%010d %010d %010d %010d]" % (0, start, end, len(b.buf) - end)
    r = run(b.bytes())
    assert [s["signed_revision"] for s in r["signatures"]] == [1, 2]
    assert r["revisions"][1]["sealed_by_signature"] is True
    assert found(r)["content_after_signature"] == "low"


def test_validation_data_update_that_repoints_the_page_tree_is_not_excused():
    b = pdfgen.Builder.resume(pdfgen.signed())
    b.obj(9, b"<< /Type /DSS >>")
    b.obj(1, b"<< /Type /Catalog /Pages 3 0 R /DSS 9 0 R >>")
    r = run(b.finish(pdfgen.trailer(id1=pdfgen.ID_B)).bytes())
    assert r["revisions"][1]["signing"] is False and found(r)["content_after_signature"] == "high"


# ---- live objects are found whatever slack the cross-reference offsets carry ------------

def one_byte_early(builder_fn, num):
    """The file from builder_fn with object `num`'s entry pointing at the newline before it."""
    data = builder_fn()
    at = data.index(b"\n%d 0 obj" % num)
    return data.replace(b"%010d 00000 n" % (at + 1), b"%010d 00000 n" % at)


@pytest.mark.parametrize("prefix", [b"", b"junk\n"])
def test_actions_and_fonts_found_with_bytes_before_the_header(prefix):
    r = run(prefix + pdfgen.javascript())
    assert r["features"]["javascript"] == 1 and len(r["fonts"]) == 1


def test_object_found_when_its_entry_points_at_preceding_white_space():
    r = run(one_byte_early(pdfgen.javascript, 7))
    assert r["features"]["javascript"] == 1 and "xref_offset_mismatch" not in found(r)


def test_live_signature_is_not_called_removed():
    for data in (b"junk\n" + pdfgen.signed(), one_byte_early(pdfgen.signed, 7)):
        r = run(data)
        assert [s["live"] for s in r["signatures"]] == [True] and "signature_removed" not in found(r)


# ---- keys cannot be hidden from the scan by text that resembles structure ----------------

def action_file(action):
    b = pdfgen.Builder()
    pdfgen._base(b, pdfgen.info(), catalog=b" /OpenAction 7 0 R")
    b.obj(7, action)
    return b.finish(pdfgen.trailer()).bytes()


def test_string_resembling_a_stream_start_does_not_hide_later_keys():
    r = run(action_file(b"<< /Note (>stream\n) /S /JavaScript /JS (app.alert(1)) >>"))
    assert r["features"]["javascript"] == 1


def test_comment_between_key_and_value_does_not_hide_an_action():
    r = run(action_file(b"<< /S %x\n/Launch /F (cmd.exe) >>"))
    assert r["features"]["launch_actions"] == 1


# ---- decoding page content is bounded whatever the filter is spelled like ------------------

def content_file(dict_body, data):
    b = pdfgen.Builder()
    pdfgen._base(b, pdfgen.info())
    b.stream(4, dict_body, data)
    return b.finish(pdfgen.trailer()).bytes()


@pytest.mark.parametrize("dict_body", [b"/Filter /FlateDecode", b"/Filter [/FlateDecode]",
                                       b"/Filter [/FlateDecode] /DecodeParms [null]"])
def test_decompression_bomb_in_page_content_stays_small(dict_body):
    bomb = zlib.compress(b"(Hi) Tj " + b"\x00" * (300 << 20), 9)  # 300 MB once inflated
    data = content_file(dict_body, bomb)
    tracemalloc.start()
    r = run(data)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert r["pages"]["details"][0]["text_operators"] is True
    assert peak < 40 << 20, "decoding was not bounded: %d MB" % (peak >> 20)


def test_large_stream_behind_an_unbounded_filter_chain_is_not_decoded():
    twice = zlib.compress(zlib.compress(b"(Hi) Tj " + b"\x00" * (300 << 20), 9), 0)
    assert len(twice) > 64 << 10
    r = run(content_file(b"/Filter [/FlateDecode /FlateDecode]", twice))
    assert r["pages"]["details"][0]["text_operators"] is None  # unknown, and nothing was inflated


# ---- structural reports say each thing once, and in both directions ------------------------

def test_one_wrong_entry_is_reported_once():
    data = pdfgen.deleted()
    entry = b"%010d 00000 n" % data.index(b"5 0 obj")
    assert data.count(entry) == 1
    r = run(data.replace(entry, b"%010d 00000 n" % (data.index(b"5 0 obj") + 3)))
    (mismatch,) = [i for i in r["tamper"]["indicators"] if i["id"] == "xref_offset_mismatch"]
    assert mismatch["detail"].startswith("1 entries")


@pytest.mark.parametrize("shift", [-7, 7])
def test_startxref_off_in_either_direction_is_reported(shift):
    data = pdfgen.simple()
    at = int(data.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    r = run(data.replace(b"startxref\n%d\n" % at, b"startxref\n%d\n" % (at + shift)))
    assert r["revisions"][0]["xref_readable"] is True
    assert any("off by" in w for w in r["warnings"])


def test_catalog_version_below_the_header_is_not_a_downgrade_in_later_revisions():
    b = pdfgen.Builder("1.7")
    pdfgen._base(b, pdfgen.info(), catalog=b" /Version /1.4")
    b.finish(pdfgen.trailer())
    for producer in ("Tool A", "Tool B"):
        b.obj(6, pdfgen.info(producer=producer))
        b.finish(pdfgen.trailer(id1=pdfgen.ID_B))
    r = run(b.bytes())
    assert r["structure"]["revision_count"] == 3 and "version_downgraded" not in found(r)


# ---- provenance names match whole product names ----------------------------------------------

@pytest.mark.parametrize("producer, expected", [
    ("TCPDF 6.6.2 (http://www.tcpdf.org)", {"library"}),
    ("dompdf 2.0.3 + CPDF", {"html_renderer"}),
    ("Princeton Typesetting 3", set()),
    ("Nitrogen Reports", set()),
    ("cpdf http://www.coherentgraphics.co.uk/", {"editor"}),
    ("mPDF 8.1.3", {"library"}),
    ("Prince 14 (www.princexml.com)", {"html_renderer"}),
    ("Nitro Pro 13", {"editor"}),
])
def test_tool_names_do_not_match_inside_other_names(producer, expected):
    r = run(pdfgen.simple(producer=producer, creator=""))
    assert {t["category"] for t in r["provenance"]["tools"]} == expected


# ---- reports are reproducible ----------------------------------------------------------------

def test_warnings_carry_no_memory_address():
    b = pdfgen.Builder()
    pdfgen._base(b, pdfgen.info(), catalog=b" /Metadata 7 0 R")
    b.stream(7, b"/Type /Metadata /Subtype /XML /Filter /FlateDecode", b"this is not deflate data")
    r = run(b.finish(pdfgen.trailer()).bytes())
    text = " ".join(r["warnings"])
    assert r["warnings"] and "0x" not in text and "BytesIO" not in text


def test_xmp_in_utf16():
    packet = pdfgen.XMP % {b"producer": b"Tool 1", b"modified": b"2024-01-02T03:04:05Z", b"extra": b""}
    for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
        xmp = parse_xmp(packet.decode("utf-8").encode(encoding))
        assert {key: value for key, value in xmp.values()}["pdf:Producer"] == "Tool 1"
    with pytest.raises(ValueError, match="DTD"):
        parse_xmp('<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'.encode("utf-16"))
