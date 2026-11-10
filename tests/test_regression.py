"""Regression tests: every fixture's full report is compared with a stored
golden copy, so any change in what the analyzer reports shows up as a diff.

Regenerate after an intended change with:
    PDFORENSIC_UPDATE_GOLDEN=1 pytest tests/test_regression.py
"""

import json
import os
import pathlib

import pdfgen
import pytest
from conftest import FIXTURES, NOW

from pdforensic import analyze, recover_revisions

GOLDEN = pathlib.Path(__file__).parent / "golden"
BUILDERS = ["simple", "updated", "deleted", "xref_stream", "hybrid", "image_only", "with_xmp", "signed",
            "unsigned", "orphan", "embedded_pdf", "javascript"]
CASES = [("gen_" + name, getattr(pdfgen, name)) for name in BUILDERS] + [
    (path.stem, path.read_bytes) for path in sorted(FIXTURES.glob("*.pdf"))]


def normalise(report):
    report = json.loads(json.dumps(report))
    del report["engine"]  # library versions differ between machines
    for rev in report["revisions"]:
        rev["qpdf_warnings"] = bool(rev["qpdf_warnings"])  # wording belongs to qpdf
    return report


@pytest.mark.parametrize("name, load", CASES, ids=[c[0] for c in CASES])
def test_report_matches_golden(name, load):
    report = normalise(analyze(load(), now=NOW))
    path = GOLDEN / (name + ".json")
    if os.environ.get("PDFORENSIC_UPDATE_GOLDEN"):
        path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    assert path.exists(), "no golden file; run with PDFORENSIC_UPDATE_GOLDEN=1"
    assert report == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("updated, original", [
    ("mutool_incremental.pdf", "reportlab.pdf"),
    ("linearized_then_updated.pdf", "qpdf_linearized.pdf"),
])
def test_recovered_revision_equals_the_original_file(tmp_path, updated, original):
    """MuPDF appended an update to `original`; cutting the result at revision 1
    must give back `original` byte for byte."""
    (first,) = recover_revisions(FIXTURES / updated, tmp_path)
    assert pathlib.Path(first["path"]).read_bytes() == (FIXTURES / original).read_bytes()


def test_linearized_file_is_not_flagged_as_updated():
    """Regression: two %%EOF markers used to be read as proof of editing."""
    report = analyze(FIXTURES / "qpdf_linearized.pdf", now=NOW)
    assert report["structure"]["eof_markers"] == 2
    assert report["structure"]["revision_count"] == 1
    assert "incremental_updates" not in {i["id"] for i in report["tamper"]["indicators"]}


def test_update_after_linearization_is_flagged():
    report = analyze(FIXTURES / "linearized_then_updated.pdf", now=NOW)
    found = {i["id"] for i in report["tamper"]["indicators"]}
    assert report["structure"]["revision_count"] == 2
    assert {"incremental_updates", "linearization_stale", "tool_changed_between_revisions"} <= found


@pytest.mark.parametrize("name, origin, generation, profile", [
    ("reportlab.pdf", "library", "programmatic", "text"),
    ("chrome_headless.pdf", "html_renderer", "programmatic", "text"),
    ("macos_quartz.pdf", "os_print", "print_to_pdf", "text"),
    ("pillow_image.pdf", "unknown", "scan_or_image_conversion", "image_only"),
])
def test_provenance_of_real_producers(name, origin, generation, profile):
    p = analyze(FIXTURES / name, now=NOW)["provenance"]
    assert (p["origin"], p["generation"], p["content_profile"]) == (origin, generation, profile)


@pytest.mark.parametrize("name", ["pdfa_org_PDF-versions1.pdf", "pdfa_org_PDF-versions2.pdf"])
def test_version_raised_by_catalog_and_update(name):
    """PDF Association pdf-differences: "The correct reported version for all
    test PDFs is PDF 1.6" (Apache-2.0, see tests/fixtures/README.md)."""
    structure = analyze(FIXTURES / name, now=NOW)["structure"]
    assert (structure["header_version"], structure["version"], structure["revision_count"]) == ("1.4", "1.6", 2)


def test_file_from_the_future():
    """PDF Association pdf-differences: a fake version and a fake filter."""
    report = analyze(FIXTURES / "pdfa_org_UnknownFilter-PageContentStream.pdf", now=NOW)
    found = {i["id"] for i in report["tamper"]["indicators"]}
    assert report["structure"]["version"] == "3.3" and report["structure"]["nonstandard_filters"] == {"XXXDecode": 1}
    assert {"unknown_pdf_version", "nonstandard_filter"} <= found and report["pages"]["count"] == 1


@pytest.mark.parametrize("name", ["bfo_pdfa2-6-1-13-t10-fail.pdf", "bfo_pdfa2-6-1-13-t11-fail.pdf"])
def test_names_that_are_not_utf8_in_third_party_files(name):
    """Files from the BFO PDF/A test suite (CC BY 3.0, see tests/fixtures/README.md)."""
    report = analyze(FIXTURES / name, now=NOW)
    assert [c["standard"] for c in report["conformance_claims"]] == ["PDF/A-2b"]
    assert report["pages"]["count"] == 1 and report["structure"]["revision_count"] == 1
