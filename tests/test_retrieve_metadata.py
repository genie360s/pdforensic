import os
from pdforensic.retrieve_metadata import extract_pdf_metadata

def test_extract_pdf_metadata_returns_dict():
    metadata = extract_pdf_metadata("tests/pdf-to-test/pdf-to-test-a.pdf")
    assert isinstance(metadata, dict)
    assert "PDF Version" in metadata
