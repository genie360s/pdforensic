"""
pdforensic - PDF forensics: metadata, revision history, tamper indicators and provenance.

analyze() and recover_revisions() are the analyzer, built on qpdf. The four
original functions wrap the bundled pdfresurrect C tool.
"""

from ._version import __version__
from .check_eof_markers import count_pdf_eof_markers
from .check_versions import check_no_of_versions
from .forensics import PdfError, analyze, format_report, recover_revisions
from .retrieve_all_versions import recover_pdf_versions
from .retrieve_metadata import extract_pdf_metadata

__all__ = [
    "__version__",
    "analyze",
    "recover_revisions",
    "format_report",
    "PdfError",
    "extract_pdf_metadata",
    "recover_pdf_versions",
    "check_no_of_versions",
    "count_pdf_eof_markers"
]
