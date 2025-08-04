#!/usr/bin/env python3

import subprocess
import argparse
import os
from .utils import get_pdfresurrect_path

def recover_pdf_versions(pdf_path):
    """
    Recover previous versions of a PDF using pdfresurrect -w.
    If previous versions are recovered, list them from the auto-created folder.

    Args:
        pdf_path (str): Path to the PDF file.

    Returns:
        str: Status message with recovered file listing if applicable.
    """
    try:
        pdfresurrect_path = get_pdfresurrect_path()
        result = subprocess.run(
            [pdfresurrect_path, '-w', pdf_path],
            capture_output=True,
            text=True,
            check=True
        )

        output = result.stdout.strip()
        print(f"\n[pdforensic output]:\n{output}\n")

        # Case 1: Only one version
        if "There is only one version of this PDF" in output:
            return "There is only one version of this PDF. No previous versions recovered."

        # Case 2: Folder exists with recovered versions
        base_name = os.path.splitext(os.path.basename(pdf_path))[0]
        version_folder = f"{base_name}-versions"

        if os.path.isdir(version_folder):
            recovered_files = os.listdir(version_folder)
            print(f"Recovered versions & summary text of change found in: {version_folder}/")
            for f in recovered_files:
                print(f"✔ {f}")
            return f"Recovered {len(recovered_files)} version(s)."
        else:
            return "Warning: Recovery folder not found, although output indicated multiple versions."

    except subprocess.CalledProcessError as e:
        return f"Error recovering PDF versions: {e}"

def cli():
    """
    Command-line interface for recovering PDF versions.
    """
    parser = argparse.ArgumentParser(description="Recover previous PDF versions using pdfresurrect")
    parser.add_argument("pdf_path", type=str, help="Path to the PDF file")
    args = parser.parse_args()

    message = recover_pdf_versions(args.pdf_path)
    print(f"\nResult: {message}")

if __name__ == "__main__":
    cli()
