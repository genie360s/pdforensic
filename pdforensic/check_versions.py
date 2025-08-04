#!/usr/bin/env python3

import subprocess
import argparse
from .utils import get_pdfresurrect_path

def check_no_of_versions(pdf_path):
    """
    Check the number of versions of a PDF file using the pdfresurrect tool.

    Args:
        pdf_path (str): The path to the PDF file.

    Returns:
        int: The number of versions found in the PDF file.
    """
    try:
        pdfresurrect_path = get_pdfresurrect_path()
        result = subprocess.run(
            [pdfresurrect_path, '-q', pdf_path],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout.strip()
        if ':' in output:
            parts = output.split(':')
            version_str = parts[1].strip()
            if version_str.isdigit():
                return int(version_str)
        print(f"Unexpected output: {output}")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"Error checking PDF versions: {e}")
        return 0

def cli():
    """
    Command-line interface for checking number of PDF versions.
    """
    parser = argparse.ArgumentParser(description="Check the number of PDF versions using pdfresurrect")
    parser.add_argument("pdf_path", type=str, help="Path to the PDF file")
    args = parser.parse_args()

    versions = check_no_of_versions(args.pdf_path)
    print(f"Number of versions found: {versions}")

if __name__ == "__main__":
    cli()
