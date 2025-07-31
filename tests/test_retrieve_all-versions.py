import os
from pdforensic.retrieve_all_versions import recover_pdf_versions

def test_recover_pdf_versions_single_version():
    result = recover_pdf_versions("tests/pdf-to-test/pdf-to-test-b.pdf")
    assert "only one version" in result.lower()

def test_recover_pdf_versions_multi_version():
    result = recover_pdf_versions("tests/pdf-to-test/pdf-to-test-a.pdf")
    assert "recovered" in result.lower()
    folder = "pdf-to-test-a-versions"
    assert os.path.exists(folder)
    assert len(os.listdir(folder)) > 0
