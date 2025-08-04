#!/usr/bin/env python3

import subprocess
import argparse
from .utils import get_pdfresurrect_path

def extract_pdf_metadata(pdf_path):
    """
    Extract PDF forensic metadata using pdfresurrect -i.

    Args:
        pdf_path (str): Path to the PDF file.

    Returns:
        dict: Metadata extracted from the PDF.
    """
    metadata = {}
    try:
        pdfresurrect_path = get_pdfresurrect_path()
        result = subprocess.run(
            [pdfresurrect_path, '-i', pdf_path],
            capture_output=True,
            text=True,
            check=True
        )

        lines = result.stdout.strip().splitlines()

        for line in lines:
            if line.strip() == "":
                continue

            # Handle Version X -- Y objects
            if line.startswith("Version") and "--" in line and "objects" in line:
                metadata["object_summary"] = line.strip()
                continue

            # Handle key: value
            if ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = value.strip().strip("()")

        return metadata

    except subprocess.CalledProcessError as e:
        print(f"Error extracting metadata: {e}")
        return {}

def cli():
    """
    Command-line interface for extracting PDF metadata.
    """
    parser = argparse.ArgumentParser(description="Extract PDF metadata using pdfresurrect")
    parser.add_argument("pdf_path", type=str, help="Path to the PDF file")
    args = parser.parse_args()

    meta = extract_pdf_metadata(args.pdf_path)
    print("Extracted PDF Metadata:")
    for key, value in meta.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    cli()
