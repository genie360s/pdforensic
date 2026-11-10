"""
pdforensic - PDF forensics: metadata, revision history, tamper indicators and provenance.

The analyzer (analyze, recover_revisions) is pure Python. The four original
functions wrap the bundled pdfresurrect C tool.
"""

from .check_eof_markers import count_pdf_eof_markers
from .check_versions import check_no_of_versions
from .forensics import PdfError, analyze, format_report, recover_revisions
from .retrieve_all_versions import recover_pdf_versions
from .retrieve_metadata import extract_pdf_metadata

__version__ = "0.2.0"

__all__ = [
    "analyze",
    "recover_revisions",
    "format_report",
    "PdfError",
    "extract_pdf_metadata",
    "recover_pdf_versions",
    "check_no_of_versions",
    "count_pdf_eof_markers"
]
