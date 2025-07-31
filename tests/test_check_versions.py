from pdforensic.check_versions import check_no_of_versions

def test_check_single_version_pdf():
    count = check_no_of_versions("tests/pdf-to-test/pdf-to-test-a.pdf")
    assert count == 1

# def test_check_multi_version_pdf():
#     count = check_no_of_versions("tests/pdf-to-test/pdf-to-test-b.pdf")
#     assert count > 1
