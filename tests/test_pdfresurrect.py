"""Integration tests: the bundled pdfresurrect C tool and the Python functions
that wrap it. Run from a temporary directory because `pdfresurrect -w` writes
its output folder into the current directory."""

import os
import subprocess

import pdfgen
import pytest
from conftest import FIXTURES

from pdforensic import analyze, check_no_of_versions, count_pdf_eof_markers, extract_pdf_metadata, recover_pdf_versions


@pytest.fixture
def workdir(tmp_path, monkeypatch, pdfresurrect):
    monkeypatch.setenv("PDFRESURRECT", pdfresurrect)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_binary_reports_its_version(pdfresurrect):
    out = subprocess.run([pdfresurrect], capture_output=True, text=True).stdout
    assert "pdfresurrect v0.24b" in out


def test_version_count(workdir):
    assert check_no_of_versions(str(FIXTURES / "reportlab.pdf")) == 1
    assert check_no_of_versions(str(FIXTURES / "mutool_incremental.pdf")) == 2


@pytest.mark.parametrize("builder", [pdfgen.simple, pdfgen.updated, pdfgen.deleted])
def test_version_count_matches_python_analyzer(workdir, builder):
    """Two independent implementations must agree on files both can read."""
    path = workdir / "doc.pdf"
    path.write_bytes(builder())
    assert check_no_of_versions(str(path)) == analyze(path)["structure"]["revision_count"]


@pytest.mark.skipif(os.name == "nt", reason="':' is not allowed in Windows file names")
def test_file_name_containing_a_colon(workdir):
    path = workdir / "report: final.pdf"
    path.write_bytes(pdfgen.updated())
    assert check_no_of_versions(str(path)) == 2


def test_metadata(workdir):
    path = workdir / "doc.pdf"
    path.write_bytes(pdfgen.updated())
    meta = extract_pdf_metadata(str(path))
    assert meta["PDF Version"] == "1.4" and meta["Versions"] == "2"
    assert meta["Producer"] == "Some PDF Editor 9"  # the value from the latest version wins
    assert meta["Title"] == "Fixture" and meta["CreationDate"] == "D:20240102030405+00'00'"


def test_metadata_limitation_is_covered_by_the_analyzer(workdir):
    """pdfresurrect prints no creator information for this ReportLab file
    (observed), while the qpdf-based analyzer reads it."""
    path = str(FIXTURES / "reportlab.pdf")
    assert "Producer" not in extract_pdf_metadata(path)
    assert analyze(path)["info"]["Producer"].startswith("ReportLab")


def test_recover_versions(workdir):
    message = recover_pdf_versions(str(FIXTURES / "mutool_incremental.pdf"))
    assert "recovered" in message.lower()
    written = sorted(p.name for p in (workdir / "mutool_incremental-versions").iterdir())
    assert "mutool_incremental-version-1.pdf" in written and "mutool_incremental-version-2.pdf" in written
    # each written version must itself open as a PDF
    for name in written:
        if name.endswith(".pdf"):
            assert analyze(workdir / "mutool_incremental-versions" / name)["pages"]["count"] == 1


def test_recover_versions_single_version(workdir):
    message = recover_pdf_versions(str(FIXTURES / "reportlab.pdf"))
    assert "only one version" in message.lower()


def test_small_file_is_accepted(workdir):
    """Regression for the vendored patch: upstream refused files under 1023 bytes."""
    path = workdir / "small.pdf"
    path.write_bytes(pdfgen.simple())
    assert path.stat().st_size < 1023
    assert check_no_of_versions(str(path)) == 1


def test_eof_marker_count(tmp_path):
    assert count_pdf_eof_markers(str(FIXTURES / "reportlab.pdf")) == 1
    assert count_pdf_eof_markers(str(FIXTURES / "mutool_incremental.pdf")) == 2
    # A linearized file has two markers yet a single revision: the marker
    # count alone does not show that a file was edited.
    assert count_pdf_eof_markers(str(FIXTURES / "qpdf_linearized.pdf")) == 2
    assert analyze(FIXTURES / "qpdf_linearized.pdf")["structure"]["revision_count"] == 1
    assert count_pdf_eof_markers(str(tmp_path / "missing.pdf")) == -1
