import os
import pathlib
import sys
from datetime import datetime, timezone

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))  # tests import the pdfgen fixture builders

FIXTURES = HERE / "fixtures"
NOW = datetime(2027, 1, 1, tzinfo=timezone.utc)  # fixed clock: reports must not depend on today


@pytest.fixture
def pdfresurrect():
    """Path of the compiled C tool. Skipped when it has not been built, unless
    PDFORENSIC_REQUIRE_BINARY is set (CI sets it, so a missing binary fails)."""
    from pdforensic.utils import get_pdfresurrect_path
    try:
        return get_pdfresurrect_path()
    except FileNotFoundError:
        if os.environ.get("PDFORENSIC_REQUIRE_BINARY"):
            raise
        pytest.skip("pdfresurrect binary not built")
