"""The documentation must name every finding and report section the code produces."""

import pathlib
import re

import pdfgen
import pytest

from pdforensic import analyze

ROOT = pathlib.Path(__file__).parent.parent
INDICATORS = set(re.findall(r'add\("([a-z_]+)",', (ROOT / "pdforensic" / "forensics.py").read_text(encoding="utf-8")))


@pytest.mark.parametrize("name", ["llms.txt", "docs/USER_GUIDE.md", "docs/PDF_FORENSICS.md"])
def test_every_indicator_is_documented(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    assert len(INDICATORS) > 20
    assert sorted(i for i in INDICATORS if "`%s`" % i not in text) == []


def test_every_report_section_is_documented():
    sections = analyze(pdfgen.simple())
    for name in ("llms.txt", "docs/USER_GUIDE.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert [k for k in sections if "`%s`" % k not in text and k != "xmp_error"] == [], name
