"""
pdforensic - Lightweight PDF forensics utility wrapping pdfresurrect and other shell tools.
"""

from .retrieve_metadata import extract_pdf_metadata
from .retrieve_all_versions import recover_pdf_versions
from .check_versions import check_no_of_versions
from .check_eof_markers import count_pdf_eof_markers

__version__ = "0.1.0"

__all__ = [
    "extract_pdf_metadata",
    "recover_pdf_versions",
    "check_no_of_versions",
    "count_pdf_eof_markers"
]
