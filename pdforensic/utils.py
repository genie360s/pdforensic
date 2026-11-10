#!/usr/bin/env python3

import os
import shutil


def get_pdfresurrect_path():
    """
    Locate the pdfresurrect binary built from src/pdfresurrect.

    Search order: the PDFRESURRECT environment variable, the copy installed
    inside this package, a CMake build in the repository, then the PATH.

    Returns:
        str: The absolute path to the pdfresurrect binary.
    """
    exe = "pdfresurrect.exe" if os.name == "nt" else "pdfresurrect"
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    candidates = [
        os.environ.get("PDFRESURRECT"),
        os.path.join(here, "_bin", exe),
        os.path.join(root, "build", exe),
        os.path.join(root, "build", "Release", exe),
        shutil.which("pdfresurrect"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return os.path.abspath(path)
    raise FileNotFoundError(
        "pdfresurrect binary not found. Build it with "
        "'cmake -B build && cmake --build build --config Release', "
        "or set the PDFRESURRECT environment variable to its path."
    )
