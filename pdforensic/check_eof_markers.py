#!/usr/bin/env python3

import argparse
import re

def count_pdf_eof_markers(pdf_path):
    """
    Count the number of %%EOF markers in a PDF file.
    
    Args:
        pdf_path (str): Path to the PDF file.

    Returns:
        int: Number of %%EOF markers.
        -1: If file not found or unreadable.
    """
    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()

        matches = re.findall(rb"%%EOF", content)
        return len(matches)

    except FileNotFoundError:
        return -1
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return -1

def cli():
    """
    Command-line interface for counting %%EOF markers in a PDF file.
    """
    parser = argparse.ArgumentParser(description="Count %%EOF markers in a PDF file")
    parser.add_argument("pdf_path", type=str, help="Path to the PDF file")
    args = parser.parse_args()

    count = count_pdf_eof_markers(args.pdf_path)
    if count == -1:
        print("❌ Could not open or read the PDF.")
    else:
        print(f"Number of %%EOF markers found: {count}")

if __name__ == "__main__":
    cli()
