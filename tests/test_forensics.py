"""Unit tests for the analysis layer (pdforensic/forensics.py)."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pdfgen
import pytest
from conftest import FIXTURES, NOW

from pdforensic import PdfError, analyze, format_report, recover_revisions
from pdforensic.forensics import parse_date, parse_xmp


def indicators(report):
    return {i["id"]: i["severity"] for i in report["tamper"]["indicators"]}


def run(data, **kw):
    report = analyze(data, now=NOW, **kw)
    json.dumps(report)  # every report must be JSON-serializable
    format_report(report)
    return report


# ---- dates and XMP ------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("D:20240102030405+02'00'", datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2)))),
    ("D:20240102030405-07'30'", datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone(-timedelta(hours=7, minutes=30)))),
    ("D:20240102030405Z", datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
    ("D:20240102030405", datetime(2024, 1, 2, 3, 4, 5)),
    ("D:2024", datetime(2024, 1, 1)),
    ("2024-01-02T03:04:05Z", datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
    ("2024-01-02T03:04:05.123+02:00", datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2)))),
    ("2024-01-02", datetime(2024, 1, 2)),
    ("D:20241340000000", None), ("yesterday", None), (None, None),
])
def test_parse_date(text, expected):
    assert parse_date(text) == expected


def test_parse_xmp_values():
    xmp = parse_xmp(pdfgen.XMP % {b"producer": b"Tool 1", b"modified": b"2024-01-02T03:04:05Z", b"extra": b""})
    by_key = {key: value for key, value in xmp.values()}
    assert by_key["pdf:Producer"] == "Tool 1"
    assert by_key["dc:title"] == ["Fixture"]
    assert by_key["pdfaid:part"] == "1" and by_key["pdfaid:conformance"] == "B"
    assert ("http://www.aiim.org/pdfa/ns/id/", "part") in xmp


def test_parse_xmp_refuses_entity_declarations():
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'
    with pytest.raises(PdfError, match="DTD"):
        parse_xmp(bomb)


# ---- clean files -----------------------------------------------------------------

def test_simple_file_has_no_indicators():
    r = run(pdfgen.simple())
    assert r["tamper"] == {**r["tamper"], "level": "none", "modified_after_creation": None, "indicators": []}
    assert r["structure"]["revision_count"] == 1 and r["structure"]["eof_markers"] == 1
    assert r["structure"]["objects"] == 6 and r["structure"]["version"] == "1.4"
    assert r["info"]["Producer"] == "pdfgen 1.0" and r["info"]["Title"] == "Fixture"
    assert r["info_dates"]["CreationDate"] == "2024-01-02T03:04:05+00:00"
    assert r["identifiers"]["permanent_equals_changing"] is True
    assert r["pages"]["count"] == 1 and r["pages"]["kinds"] == {"text": 1}
    assert r["fonts"] == [{"name": "Helvetica", "subtype": "Type1", "embedded": False, "subset": False}]
    assert r["file"]["sha256"] == hashlib.sha256(pdfgen.simple()).hexdigest()
    assert r["file"]["md5"] == hashlib.md5(pdfgen.simple()).hexdigest()
    assert r["encryption"] == {"encrypted": False} and r["warnings"] == []


def test_objects_inside_object_streams_are_read():
    r = run(pdfgen.xref_stream())
    assert r["revisions"][0]["xref_type"] == "stream"
    assert r["structure"]["object_streams"] == 1 and r["structure"]["objects"] == 8
    assert r["info"]["Producer"] == "pdfgen objstm"
    assert r["fonts"][0]["name"] == "Helvetica" and r["pages"]["kinds"] == {"text": 1}
    assert r["tamper"]["indicators"] == []


def test_hybrid_reference_file_is_one_revision():
    """Microsoft Office writes this layout: two %%EOF markers from the start."""
    r = run(pdfgen.hybrid())
    s = r["structure"]
    assert (s["eof_markers"], s["revision_count"], s["hybrid_reference"]) == (2, 1, True)
    assert r["revisions"][0]["xref_type"] == "hybrid-stream+table"
    assert s["objects"] == 9 and s["object_streams"] == 1  # 1-6, plus 7 (compressed), 10 and 11
    assert r["tamper"]["indicators"] == [] and r["warnings"] == []


def test_update_after_hybrid_file_is_still_found():
    b = pdfgen.Builder.resume(pdfgen.hybrid())
    b.obj(6, pdfgen.info(producer="Some PDF Editor 9"))
    r = run(b.finish(pdfgen.trailer(id1=pdfgen.ID_B)).bytes())
    assert r["structure"]["revision_count"] == 2
    assert r["revisions"][1]["changes"] == [{"object": 6, "change": "modified", "type": "Info"}]
    assert indicators(r)["incremental_updates"] == "medium"


def test_update_that_only_frees_objects_is_not_mistaken_for_hybrid():
    b = pdfgen.Builder.resume(pdfgen.updated())
    b.free(7)
    r = run(b.finish(pdfgen.trailer(id1=pdfgen.ID_B)).bytes())
    assert r["structure"]["revision_count"] == 3 and r["structure"]["hybrid_reference"] is False


def test_embedded_pdf_does_not_create_a_revision():
    r = run(pdfgen.embedded_pdf())
    assert r["structure"]["eof_markers"] == 2 and r["structure"]["revision_count"] == 1
    assert r["features"]["embedded_files"] == 1
    assert r["tamper"]["indicators"] == []


def test_not_a_pdf_raises():
    with pytest.raises(PdfError):
        analyze(b"\x89PNG\r\n\x1a\n not a pdf")


# ---- revision history --------------------------------------------------------------

def test_incremental_update_is_reported_with_its_changes():
    r = run(pdfgen.updated())
    assert indicators(r) == {"incremental_updates": "medium", "id_mismatch": "low", "dates_differ": "low",
                             "tool_changed_between_revisions": "medium"}
    assert r["tamper"]["level"] == "medium" and r["tamper"]["modified_after_creation"] is True
    first, second = r["revisions"]
    assert first["objects"] == {"added": 6, "modified": 0, "deleted": 0}
    assert second["objects"] == {"added": 1, "modified": 3, "deleted": 0}
    assert second["changes"] == [
        {"object": 3, "change": "modified", "type": "Page"},
        {"object": 4, "change": "modified", "type": "Stream"},
        {"object": 6, "change": "modified", "type": "Info"},
        {"object": 7, "change": "added", "type": "Annot/FreeText"},
    ]
    assert first["info"]["Producer"] == "pdfgen 1.0" and second["info"]["Producer"] == "Some PDF Editor 9"
    assert second["prev"] == first["startxref"]
    assert r["features"]["annotations"] == {"FreeText": 1}


def test_revision_hash_is_the_hash_of_the_original_file():
    r = run(pdfgen.updated())
    assert r["revisions"][0]["sha256"] == hashlib.sha256(pdfgen.simple()).hexdigest()
    assert r["revisions"][1]["sha256"] == r["file"]["sha256"]


def test_deleted_objects():
    r = run(pdfgen.deleted())
    assert r["structure"]["revision_count"] == 3
    assert r["revisions"][2]["objects"] == {"added": 0, "modified": 1, "deleted": 1}
    assert {"object": 7, "change": "deleted", "type": "Annot/FreeText"} in r["revisions"][2]["changes"]
    assert indicators(r)["deleted_objects"] == "low"
    assert r["features"]["annotations"] == {}  # the annotation is gone from the current document


def test_recover_revisions_writes_exact_prefixes(tmp_path):
    source = tmp_path / "doc.pdf"
    source.write_bytes(pdfgen.deleted())
    written = recover_revisions(source, tmp_path / "out")
    assert [w["revision"] for w in written] == [1, 2]
    assert (tmp_path / "out" / "doc-rev1.pdf").read_bytes() == pdfgen.simple()
    assert (tmp_path / "out" / "doc-rev2.pdf").read_bytes() == pdfgen.updated()
    assert written[0]["sha256"] == hashlib.sha256(pdfgen.simple()).hexdigest()
    # a recovered revision is itself a clean single-revision file
    assert run((tmp_path / "out" / "doc-rev1.pdf").read_bytes())["tamper"]["indicators"] == []


def test_recover_single_revision_writes_nothing(tmp_path):
    assert recover_revisions(pdfgen.simple(), tmp_path / "out") == []
    assert not (tmp_path / "out").exists()
    assert len(recover_revisions(pdfgen.simple(), tmp_path / "out", include_current=True)) == 1


# ---- metadata consistency -------------------------------------------------------------

def test_xmp_and_conformance_claim():
    r = run(pdfgen.with_xmp())
    assert r["xmp"]["pdf:Producer"] == "pdfgen 1.0"
    assert r["conformance_claims"] == [{"standard": "PDF/A-1b", "iso": "ISO 19005-1", "validated": False,
                                        "conformance": None, "source": "XMP pdfaid:part=1 conformance=B"}]
    assert r["tamper"]["indicators"] == []


def test_info_and_xmp_producer_disagree():
    r = run(pdfgen.with_xmp(xmp_producer=b"Other Tool 2"))
    assert indicators(r) == {"info_xmp_mismatch": "low"}


def test_info_moddate_newer_than_xmp():
    """ISO 32000-1 14.3.2 and XMP Specification Part 3, 2.2.2: an Info ModDate
    later than xmp:MetadataDate means the file was saved again by software
    that does not maintain XMP."""
    r = run(pdfgen.with_xmp(modified="D:20240601000000+00'00'"))
    found = indicators(r)
    assert found == {"info_newer_than_xmp": "medium", "info_xmp_mismatch": "low", "dates_differ": "low"}
    assert r["tamper"]["modified_after_creation"] is True
    # a difference of seconds is two timestamps taken during one save, not a second save
    r = run(pdfgen.with_xmp(modified="D:20240102030420+00'00'"))
    assert "info_newer_than_xmp" not in indicators(r)
    # exactly eight hours apart: the same moment written with two UTC offsets
    r = run(pdfgen.with_xmp(modified="D:20240102110405+00'00'"))
    assert indicators(r)["info_newer_than_xmp"] == "info"


DC = b' xmlns:dc="http://purl.org/dc/elements/1.1/"'
RDF = b' xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'


def info_with(extra):
    return pdfgen.info()[:-3] + b" " + extra + b" >>"


def test_subject_author_and_keywords_are_compared_with_xmp():
    """XMP Specification Part 3, Table 20: Subject maps to dc:description,
    Author to the first dc:creator (or all of them joined), Keywords to pdf:Keywords."""
    xmp = (b"<dc:description" + DC + b"><rdf:Alt" + RDF + b'><rdf:li xml:lang="x-default">about lofts</rdf:li></rdf:Alt>'
           b"</dc:description>"
           b"<dc:creator" + DC + b"><rdf:Seq" + RDF + b"><rdf:li>Ann Lee</rdf:li><rdf:li>Bo Chan</rdf:li></rdf:Seq></dc:creator>")
    same = run(pdfgen.with_xmp(xmp_extra=xmp, info_body=info_with(b"/Subject (about lofts) /Author (Ann Lee; Bo Chan)")))
    assert same["tamper"]["indicators"] == []
    first = run(pdfgen.with_xmp(xmp_extra=xmp, info_body=info_with(b"/Subject (about lofts) /Author (Ann Lee)")))
    assert first["tamper"]["indicators"] == []
    one = xmp.replace(b"<rdf:li>Ann Lee</rdf:li><rdf:li>Bo Chan</rdf:li>", b"<rdf:li>Lee , Ann</rdf:li>")
    surname_first = run(pdfgen.with_xmp(xmp_extra=one, info_body=info_with(b"/Subject (about lofts) /Author (Lee, Ann)")))
    assert surname_first["tamper"]["indicators"] == []  # one creator whose name contains a comma
    differs = run(pdfgen.with_xmp(xmp_extra=xmp, info_body=info_with(b"/Subject (loft) /Author (Someone Else)")))
    titles = sorted(i["title"] for i in differs["tamper"]["indicators"])
    assert titles == ["Info Author and XMP disagree", "Info Subject and XMP disagree"]
    assert differs["tamper"]["level"] == "info"


def test_xmp_history_is_reported():
    """XMP Specification Part 2, 1.2.4: xmpMM:History is a list of ResourceEvents."""
    xmp = (b'<xmpMM:History xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"'
           b' xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#"><rdf:Seq' + RDF + b">"
           b'<rdf:li stEvt:action="created" stEvt:when="2024-01-02T03:04:05Z"'
           b' stEvt:softwareAgent="Adobe InDesign 15.1 (Macintosh)"/>'
           b'<rdf:li rdf:parseType="Resource"><stEvt:action>saved</stEvt:action><stEvt:when>2024-01-03T10:00:00Z</stEvt:when>'
           b"<stEvt:softwareAgent>Adobe Acrobat Pro DC</stEvt:softwareAgent><stEvt:changed>/metadata</stEvt:changed></rdf:li>"
           b"</rdf:Seq></xmpMM:History>")
    r = run(pdfgen.with_xmp(xmp_extra=xmp))
    assert r["xmp_history"] == [
        {"action": "created", "when": "2024-01-02T03:04:05Z", "software_agent": "Adobe InDesign 15.1 (Macintosh)",
         "changed": None, "parameters": None},
        {"action": "saved", "when": "2024-01-03T10:00:00Z", "software_agent": "Adobe Acrobat Pro DC",
         "changed": "/metadata", "parameters": None}]
    assert indicators(r)["xmp_history"] == "info"
    tools = {(t["field"], t["tool"]) for t in r["provenance"]["tools"]}
    assert ("XMP history agent", "Adobe InDesign") in tools and ("XMP history agent", "Adobe Acrobat") in tools
    assert r["provenance"]["origin"] == "design"


def test_custom_info_keys_in_xmp_are_unescaped():
    """XMP Specification Part 3, 2.2.1: characters that cannot appear in an XML
    name are written as U+2182 followed by four hexadecimal digits."""
    xmp = '<pdfx:Web\u2182002012 xmlns:pdfx="http://ns.adobe.com/pdfx/1.3/">value</pdfx:Web\u2182002012>'.encode()
    r = run(pdfgen.with_xmp(xmp_extra=xmp))
    assert r["xmp"]["pdfx:Web 12"] == "value"


def test_one_claim_per_standard():
    xmp = (b'<pdfxid:GTS_PDFXVersion xmlns:pdfxid="http://www.npes.org/pdfx/ns/id/">PDF/X-4</pdfxid:GTS_PDFXVersion>'
           b'<pdfx:GTS_PDFXVersion xmlns:pdfx="http://ns.adobe.com/pdfx/1.3/">PDF/X-4</pdfx:GTS_PDFXVersion>')
    claims = run(pdfgen.with_xmp(xmp_extra=xmp))["conformance_claims"]
    assert [(c["standard"], c["iso"]) for c in claims] == [("PDF/A-1b", "ISO 19005-1"), ("PDF/X-4", "ISO 15930")]
    assert claims[1]["conformance"] is None
    assert claims[1]["source"] == "XMP pdfxid:GTS_PDFXVersion; XMP pdfx:GTS_PDFXVersion"


def test_moddate_before_creation():
    r = run(pdfgen.simple(created="D:20240102030405+00'00'", modified="D:20230101000000+00'00'"))
    assert indicators(r) == {"moddate_before_creation": "low"}
    # a few seconds the "wrong" way round is a writer habit (seen with Canva), not a finding
    r = run(pdfgen.simple(created="D:20240102030405+00'00'", modified="D:20240102030401+00'00'"))
    assert indicators(r) == {"moddate_before_creation": "info"}


def test_small_gap_between_dates_is_only_informational():
    r = run(pdfgen.simple(modified="D:20240102030407+00'00'"))
    assert indicators(r) == {"dates_differ": "info"} and r["tamper"]["modified_after_creation"] is None


def test_future_date():
    r = run(pdfgen.simple(created="D:20300101000000+00'00'", modified="D:20300101000000+00'00'"))
    assert indicators(r) == {"future_date": "low"}


# ---- signatures ----------------------------------------------------------------------

def test_signature_covering_the_whole_file():
    r = run(pdfgen.signed())
    (sig,) = r["signatures"]
    assert sig["subfilter"] == "adbe.pkcs7.detached" and sig["signer_name"] == "Test Signer"
    assert sig["covers_whole_file"] is True and sig["signed_revision"] == 1 and sig["live"] is True
    assert sig["byte_range_shape_ok"] is True and sig["date_iso"] == "2024-01-02T03:04:05+00:00"
    assert r["features"]["acroform"] is True and r["revisions"][0]["signing"] is True
    assert r["tamper"]["indicators"] == []


def test_content_appended_after_signature():
    r = run(pdfgen.signed(appended=True))
    found = indicators(r)
    assert found["content_after_signature"] == "high" and found["incremental_updates"] == "medium"
    assert r["signatures"][0]["signed_revision"] == 1 and r["signatures"][0]["bytes_after_signature"] > 0
    assert r["tamper"]["level"] == "high"


def test_preflight_ticket_sealed_by_its_signature():
    """GWG Universal Proof of Preflight: the ticket is XMP in its own namespace,
    sealed by a signature named exactly "Preflight Ticket Signature"."""
    r = run(pdfgen.signed(signer=b"Preflight Ticket Signature", xmp_extra=pdfgen.TICKET))
    assert r["preflight_ticket"] == {
        "profile_name": "MagazineAds_1v3", "profile_creator": "Adobe Acrobat Preflight",
        "profile_creator_version": "8.0", "profile_format_version": None, "results": "Success",
        "results_description": None, "executed_date": "2024-01-02T03:04:05Z",
        "profile_fingerprint": "ff68-7293-a8ee-524c", "signed": True, "signature_covers_whole_file": True}
    assert indicators(r) == {"preflight_ticket": "info"}


def test_preflight_ticket_without_its_signature():
    r = run(pdfgen.with_xmp(xmp_extra=pdfgen.TICKET))
    assert r["preflight_ticket"]["signed"] is False
    assert indicators(r) == {"preflight_ticket": "info", "preflight_ticket_unsealed": "low"}
    # a signature under another name does not seal the ticket
    r = run(pdfgen.signed(xmp_extra=pdfgen.TICKET))
    assert indicators(r)["preflight_ticket_unsealed"] == "low"


def test_file_changed_after_its_preflight_ticket_was_sealed():
    r = run(pdfgen.signed(appended=True, signer=b"Preflight Ticket Signature", xmp_extra=pdfgen.TICKET))
    assert r["preflight_ticket"]["signed"] is True and r["preflight_ticket"]["signature_covers_whole_file"] is False
    assert indicators(r)["content_after_signature"] == "high"


def test_file_without_a_preflight_ticket():
    assert run(pdfgen.with_xmp())["preflight_ticket"] is None


def test_removed_signature_is_still_found():
    r = run(pdfgen.unsigned())
    (sig,) = r["signatures"]
    assert sig["live"] is False and sig["signed_revision"] == 1
    assert indicators(r)["signature_removed"] == "high"
    assert r["features"]["acroform"] is False


# ---- structural anomalies ---------------------------------------------------------------

def test_trailing_data():
    r = run(pdfgen.simple() + b"APPENDED PAYLOAD")
    assert indicators(r) == {"trailing_data": "low"} and r["structure"]["trailing_bytes"] == 16


def test_update_that_lost_its_trailer_leaves_the_previous_revision_in_force():
    data = pdfgen.updated()
    r = run(data[: data.rindex(b"trailer")])  # the second revision loses its trailer
    assert r["structure"]["revision_count"] == 1 and r["info"]["Producer"] == "pdfgen 1.0"
    assert indicators(r) == {"trailing_data": "low"}


def test_file_whose_final_trailer_is_missing_is_still_read():
    """Regression: qpdf must be given the whole file. A linearized file cut
    before its final trailer keeps only the %%EOF near its start, and reading
    just up to there found no pages at all."""
    data = (FIXTURES / "qpdf_linearized.pdf").read_bytes()
    r = run(data[: data.rindex(b"trailer")])
    assert r["pages"]["count"] == 1 and r["info"]["Producer"].startswith("ReportLab")
    found = indicators(r)
    assert found["structural_damage"] == "medium" and found["xref_unreadable"] == "medium"


def test_tolerated_syntax_problems_are_information_only():
    data = pdfgen.simple()
    assert b"/Length 51" in data
    data = data.replace(b"/Length 51", b"/Length 40")  # a wrong stream length, which readers tolerate
    r = run(data)
    assert indicators(r) == {"syntax_warnings": "info"}
    assert r["tamper"]["level"] == "info" and r["tamper"]["modified_after_creation"] is None


def test_xref_entry_at_offset_zero_is_ignored():
    """macOS Quartz writes in-use entries at offset 0 for unused object numbers."""
    b = pdfgen.Builder()
    pdfgen._base(b, pdfgen.info())
    b.entries[7] = 0
    b.size = 8
    r = run(b.finish(pdfgen.trailer()).bytes())
    assert "xref_offset_mismatch" not in indicators(r)


def test_unreferenced_object():
    r = run(pdfgen.orphan())
    assert indicators(r) == {"unreferenced_objects": "low"}
    assert "[9]" in r["tamper"]["indicators"][0]["detail"]
    assert r["structure"]["object_headers"] == r["structure"]["objects"] + 1


def test_wrong_startxref():
    r = run(pdfgen.simple().replace(b"startxref\n", b"startxref\n9"))
    found = indicators(r)
    assert found["xref_unreadable"] == "medium" and found["structural_damage"] == "medium"
    assert r["info"]["Producer"] == "pdfgen 1.0"  # qpdf rebuilt the table, so content is still read


def test_wrong_object_offset():
    data = pdfgen.simple()
    at = data.index(b"0000000015")
    r = run(data[:at] + b"0000000019" + data[at + 10:])
    assert indicators(r)["structural_damage"] == "medium"


def test_truncated_file_reports_raw_structure_only():
    data = pdfgen.simple()
    r = run(data[: data.index(b"/Info")])
    assert r["revisions"][0]["xref_readable"] is False and indicators(r)["xref_unreadable"] == "medium"


def test_bytes_before_header():
    r = run(b"\n\n" + pdfgen.simple())
    assert r["structure"]["header_offset"] == 2 and r["info"]["Producer"] == "pdfgen 1.0"


def test_filter_the_standard_does_not_define():
    """ISO 32000-1 7.4, Table 6 lists the ten standard filters."""
    r = run(pdfgen.odd_filter())
    assert r["structure"]["nonstandard_filters"] == {"XXXDecode": 1}
    assert indicators(r)["nonstandard_filter"] == "low"
    assert r["pages"]["details"][0]["text_operators"] is None  # the content could not be read


def test_handler_names_are_not_stream_filters():
    """/Filter in a signature or encryption dictionary names a handler."""
    assert run(pdfgen.signed())["structure"]["nonstandard_filters"] == {}
    assert run((FIXTURES / "qpdf_aes256.pdf").read_bytes())["structure"]["nonstandard_filters"] == {}
    assert run(pdfgen.image_only())["structure"]["nonstandard_filters"] == {}  # DCTDecode is standard


def test_version_is_tracked_through_revisions():
    """Header 1.4, catalog 1.5, update to 1.6: the file is PDF 1.6 (7.5.2)."""
    r = run(pdfgen.version_steps())
    s = r["structure"]
    assert (s["header_version"], s["catalog_version"], s["version"]) == ("1.4", "1.6", "1.6")
    assert [x["catalog_version"] for x in r["revisions"]] == ["1.5", "1.6"]
    assert "version_downgraded" not in indicators(r)


def test_update_must_not_lower_the_version():
    r = run(pdfgen.version_steps(first=b"1.7", second=b"1.5"))
    assert indicators(r)["version_downgraded"] == "low"


def test_unpublished_version_number():
    r = run(pdfgen.simple().replace(b"%PDF-1.4", b"%PDF-3.1"))
    assert r["structure"]["specification"] == "not a published PDF version"
    assert indicators(r) == {"unknown_pdf_version": "low"}
    assert run(pdfgen.simple())["structure"]["specification"] == "Adobe PDF Reference (PDF 1.4)"


def test_startxref_slightly_off_is_tolerated_and_reported():
    data = pdfgen.simple()
    at = int(data.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    r = run(data.replace(b"startxref\n%d\n" % at, b"startxref\n%d\n" % (at - 9)))
    assert r["revisions"][0]["xref_readable"] is True and r["revisions"][0]["xref_type"] == "table"
    assert any("off by 9 bytes" in w for w in r["warnings"])
    assert indicators(r)["structural_damage"] == "medium"  # qpdf had to search for it too


def test_pdfx_conformance_level():
    """Older PDF/X files state the level in GTS_PDFXConformance."""
    body = pdfgen.info()[:-3] + b" /GTS_PDFXVersion (PDF/X-1:2001) /GTS_PDFXConformance (PDF/X-1a:2001) >>"
    b = pdfgen.Builder()
    pdfgen._base(b, body)
    (claim,) = run(b.finish(pdfgen.trailer()).bytes())["conformance_claims"]
    assert (claim["standard"], claim["conformance"], claim["iso"]) == ("PDF/X-1:2001", "PDF/X-1a:2001", "ISO 15930")


# ---- content and provenance ---------------------------------------------------------------

@pytest.mark.parametrize("content", [
    b"BT /F1 12 Tf 72 720 Td (Hello) Tj ET",
    b"BT /F1 12 Tf 72 720 Td(Hello)Tj ET",                # no space before the operator
    b"BT /F1 12 Tf 72 720 Td[(Hel)-20(lo)]TJ ET",
    b"BT /F1 12 Tf 72 720 Td <48656C6C6F>Tj ET",
    b"BT /F1 12 Tf 14 TL 72 720 Td (Hello)' ET",
])
def test_text_operators_are_recognised_however_they_are_spaced(content):
    b = pdfgen.Builder()
    pdfgen._base(b, pdfgen.info(), content=content)
    r = run(b.finish(pdfgen.trailer()).bytes())
    assert r["pages"]["details"][0]["text_operators"] is True and r["pages"]["kinds"] == {"text": 1}


def test_page_without_text_or_images():
    b = pdfgen.Builder()
    pdfgen._base(b, pdfgen.info(), content=b"0 0 m 100 100 l S /xTj gs /Tjx gs", resources=b"")  # no Tj operator
    r = run(b.finish(pdfgen.trailer()).bytes())
    assert r["pages"]["details"][0]["text_operators"] is False and r["pages"]["kinds"] == {"no_text_no_images": 1}


def test_only_painted_images_count_for_a_page():
    """A resource dictionary may list images the page never draws."""
    b = pdfgen.Builder()
    pdfgen._base(b, pdfgen.info(), resources=b"/Font << /F1 5 0 R >> /XObject << /Im1 7 0 R >>")
    b.stream(7, b"/Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceGray "
                b"/BitsPerComponent 8 /Filter /DCTDecode", b"\xff\xd8\xff\xd9")
    r = run(b.finish(pdfgen.trailer()).bytes())
    assert r["pages"]["kinds"] == {"text": 1} and r["pages"]["details"][0]["images"] == 0
    assert r["images"]["count"] == 1  # the image is still in the file's inventory


def test_image_only_page_looks_like_a_scan():
    r = run(pdfgen.image_only())
    assert r["pages"]["kinds"] == {"image_only": 1} and r["images"]["count"] == 1
    assert r["images"]["details"][0] == {**r["images"]["details"][0], "width": 2, "height": 2,
                                         "filter": ["DCTDecode"], "color_space": "DeviceGray"}
    assert r["provenance"]["content_profile"] == "image_only"
    assert r["provenance"]["generation"] == "scan_or_image_conversion"


def test_image_with_invisible_text_looks_like_ocr():
    r = run(pdfgen.image_only(hidden_text=True))
    assert r["pages"]["kinds"] == {"image_with_hidden_text": 1}
    assert r["provenance"]["content_profile"] == "image_with_hidden_text"


@pytest.mark.parametrize("creator, producer, origin, generation", [
    ("Microsoft® Excel® for Microsoft 365", "Microsoft® Excel® for Microsoft 365", "spreadsheet", "exported_from_application"),
    ("Acrobat PDFMaker 17 for Excel", "Adobe PDF Library 15.0", "spreadsheet", "exported_from_application"),
    ("Calc", "LibreOffice 7.5", "spreadsheet", "exported_from_application"),
    ("Microsoft® Word 2016", "Microsoft® Word 2016", "word_processor", "exported_from_application"),
    ("Writer", "LibreOffice 7.5", "word_processor", "exported_from_application"),
    ("Chromium", "Skia/PDF m120", "browser", "browser_print"),
    ("wkhtmltopdf 0.12.6", "Qt 5.15.2", "html_renderer", "programmatic"),
    ("JasperReports Library version 6.20.0", "iText 2.1.7 by 1T3XT", "report_engine", "programmatic"),
    ("", "iText® 7.1.15 ©2000-2021 iText Group NV", "library", "programmatic"),
    ("", "TCPDF 6.6.2 (http://www.tcpdf.org)", "library", "programmatic"),
    ("TeX", "pdfTeX-1.40.25", "typesetting", "exported_from_application"),
    ("PScript5.dll Version 5.2.2", "Acrobat Distiller 11.0 (Windows)", "os_print", "print_to_pdf"),
    ("", "Adobe Acrobat Pro DC 20.0", "editor", "post_processed"),
    ("CutePDF Writer", "GPL Ghostscript 9.50", "os_print", "print_to_pdf"),
    ("In-house billing 3", "Unknown Engine", "unknown", "unknown"),
])
def test_provenance_from_metadata(creator, producer, origin, generation):
    r = run(pdfgen.simple(creator=creator, producer=producer))
    assert (r["provenance"]["origin"], r["provenance"]["generation"]) == (origin, generation)
    assert all(t["value"] in (creator, producer) for t in r["provenance"]["tools"])


def test_editing_tool_is_flagged_as_information_only():
    r = run(pdfgen.simple(producer="iLovePDF"))
    assert indicators(r) == {"editing_tool_named": "info"}


@pytest.mark.parametrize("obfuscated", [False, True])
def test_javascript_is_counted_even_with_escaped_names(obfuscated):
    r = run(pdfgen.javascript(obfuscated))
    assert r["features"]["javascript"] == 1 and r["features"]["open_action"] is True


# ---- encryption (files written by qpdf) ---------------------------------------------------

@pytest.mark.parametrize("name, method, bits", [
    ("qpdf_rc4_128.pdf", "rc4", 128), ("qpdf_aes128.pdf", "aes", 128), ("qpdf_aes256.pdf", "aesv3", 256)])
def test_owner_password_only_files_are_decrypted(name, method, bits):
    r = run((FIXTURES / name).read_bytes())
    e = r["encryption"]
    assert (e["encrypted"], e["decrypted"], e["password"], e["bits"]) == (True, True, "empty", bits)
    assert e["stream_method"] == method
    assert r["info"]["Producer"].startswith("ReportLab") and r["pages"]["kinds"] == {"text": 1}


def test_user_password_is_required_then_accepted():
    data = (FIXTURES / "qpdf_aes256_userpw.pdf").read_bytes()
    locked = run(data)
    assert locked["encryption"]["decrypted"] is False and locked["encryption"]["password"] == "required"
    assert locked["info"] is None and locked["structure"]["revision_count"] == 1
    opened = run(data, password="secret")
    assert opened["encryption"]["decrypted"] is True and opened["info"]["Title"] == "Invoice 0042"
