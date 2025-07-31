from pdforensic.check_eof_markers import count_pdf_eof_markers

def test_count_eof_in_single_version_pdf():
    count = count_pdf_eof_markers("tests/pdf-to-test/pdf-to-test-b.pdf")
    assert count == 1

def test_count_eof_in_multi_version_pdf():
    count = count_pdf_eof_markers("tests/pdf-to-test/pdf-to-test-a.pdf")
    assert count > 1
