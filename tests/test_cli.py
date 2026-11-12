"""Integration tests: the pdforensic command line, end to end in a subprocess."""

import json
import subprocess
import sys

import pdfgen
from conftest import FIXTURES


def cli(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "pdforensic.cli", *map(str, args)],
                          capture_output=True, text=True, cwd=cwd)


def test_analyze_json(tmp_path):
    source = tmp_path / "updated.pdf"
    source.write_bytes(pdfgen.updated())
    result = cli("analyze", source, "--json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["file"]["path"] == str(source)
    assert report["structure"]["revision_count"] == 2
    assert report["tamper"]["level"] == "medium"


def test_analyze_text_report():
    result = cli("analyze", FIXTURES / "mutool_incremental.pdf")
    assert result.returncode == 0, result.stderr
    assert "Revisions   2" in result.stdout
    assert "modified object 5 (Info)" in result.stdout
    assert "Tamper indicators: level=medium" in result.stdout


def test_recover_writes_previous_revisions(tmp_path):
    result = cli("recover", FIXTURES / "mutool_incremental.pdf", "-o", tmp_path / "out")
    assert result.returncode == 0, result.stderr
    recovered = tmp_path / "out" / "mutool_incremental-rev1.pdf"
    assert recovered.read_bytes() == (FIXTURES / "reportlab.pdf").read_bytes()
    assert "revision 1" in result.stdout


def test_recover_single_revision(tmp_path):
    result = cli("recover", FIXTURES / "reportlab.pdf", cwd=tmp_path)
    assert result.returncode == 0 and "nothing to recover" in result.stdout
    assert list(tmp_path.iterdir()) == []


def test_password_option():
    locked = json.loads(cli("analyze", FIXTURES / "qpdf_aes256_userpw.pdf", "--json").stdout)
    assert locked["encryption"]["decrypted"] is False
    opened = json.loads(cli("analyze", FIXTURES / "qpdf_aes256_userpw.pdf", "--json", "--password", "secret").stdout)
    assert opened["encryption"]["decrypted"] is True


def test_errors_exit_with_status_2(tmp_path):
    not_pdf = tmp_path / "note.txt"
    not_pdf.write_text("plain text")
    result = cli("analyze", not_pdf)
    assert result.returncode == 2 and "not a PDF" in result.stderr
    assert cli("analyze", tmp_path / "missing.pdf").returncode == 2


def test_version_comes_from_the_version_file():
    """VERSION at the top of the repository is the single source."""
    import pathlib

    import pdforensic

    expected = (pathlib.Path(__file__).parent.parent / "VERSION").read_text(encoding="utf-8").strip()
    assert pdforensic.__version__ == expected
    assert cli("--version").stdout.strip() == "pdforensic " + expected
    assert pdforensic.analyze(pdfgen.simple())["engine"]["pdforensic"] == expected
