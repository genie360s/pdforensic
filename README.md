# 📄 pdforensic


> A lightweight Python toolkit for forensic analysis of PDF files using [pdfresurrect](https://github.com/enferex/pdfresurrect) and unix kernel shell utilities.

**pdforensic** wraps common PDF forensic techniques into an easy-to-use Python and CLI interface — allowing you to extract metadata, recover previous versions, count EOF markers, and inspect version layers of PDF files.

## Project Directory
```
.
├── bin
│   ├── pdfresurrect
│   └── pdfresurrect.1
├── LICENSE
├── pdforensic
│   ├── __init__.py
├── README.md
├── setup.py
└── tests
    ├── pdf-to-test
    │   ├── pdf-to-test-a.pdf
    │   └── pdf-to-test-b.pdf
    ├── test_check_eof_markers.py
    ├── test_check_versions.py
    ├── test_retrieve_all-versions.py
    └── test_retrieve_metadata.py
```
## The Package

This package has been built to work on unix kernel i.e., linux OS and MacOS.

You will require Python 3.13.x to work with this package.

This package is an ongoing experiment to understand how to check for an edited PDF and automate the process.

It is built on top of [pdfresurrect](https://github.com/enferex/pdfresurrect) which is a C tool that reads the PDF at it's lowest level extracting metadata , object streams , check for previous versions by checking for cross-referencing of streams and also able to rewrite previous versions.

The **pdfresurrect** functionalities have been wrapped to be reusable quickly with Python.

An additional functionality from my PDF research has been added that check for `%%EOF` markers its absence means the PDF is corrupted and not in a proper format. A linearized or an original or freshly saved has 1 `%%EOF` marker , more than 1 means the PDF has been tampered with.

Hence you can use above functionalities to build a PDF verification algorithim if you do now what type of PDF file you will be processing by comparing it's properties against new incoming PDF's.

## 🐍 Using the Python Package

You can use **pdforensic** directly from Python code by importing its core functions.

### 📦 Importable Functions

```python
from pdforensic import (
    extract_pdf_metadata,
    recover_pdf_versions,
    count_pdf_eof_markers,
    check_no_of_versions
)
```
1. Extract PDF Metadata

```python
from pdforensic import extract_pdf_metadata

metadata = extract_pdf_metadata("tests/pdf-to-test/pdf-to-test-a.pdf")
print(metadata)
```
Returns:

```python

{
  'Versions': '1',
  'PDF Version': '1.4',
  'Title': 'My Document',
  'Producer': 'Skia/PDF',
  ...
}
```

2. Recover Previous Versions

```python

from pdforensic import recover_pdf_versions

message = recover_pdf_versions("tests/pdf-to-test/pdf-to-test-b.pdf")
print(message)
```

Example output:
```python
Recovered 2 version(s). Found in: pdf-to-test-b-versions/
```

3. Count %%EOF Markers

```python
from pdforensic import count_pdf_eof_markers

count = count_pdf_eof_markers("tests/pdf-to-test/pdf-to-test-a.pdf")
print(f"EOF markers: {count}")
```

4. Check Number of PDF Versions

```python
from pdforensic import check_no_of_versions

num_versions = check_no_of_versions("tests/pdf-to-test/pdf-to-test-a.pdf")
print(f"PDF contains {num_versions} version(s).")
```

**🧪 Pro Tip**
You can integrate these tools into a PDF auditing script or pipeline for digital forensics, penetration testing, academic research, or version tracking.

### 📦 Using CLI

**🔧 Command-Line Interface (CLI)**

Once installed (with pip install -e .), the following CLI commands are available:

**Command	Description**

```
pdf-meta	Extract metadata from a PDF file
pdf-recover	Recover previous versions of a PDF
pdf-eof	Count %%EOF markers in a PDF
pdf-versions	Check number of versions in a PDF (via -q)
```

Example Usage
```bash

pdf-meta <pdf_path>

pdf-recover <pdf_path>

pdf-eof <pdf_path>

pdf-versions <pdf_path>

```
## 🛠️ Installation

### Option 1: Clone and Install from GitHub (Recommended)

```bash
git clone https://github.com/yourusername/pdforensic.git
cd pdforensic
pip install -e .
#This installs pdforensic in editable mode, meaning any changes you make to the code will take effect immediately.
```

### Option 2: Install with Dev Dependencies (for testing and development)
```bash
pip install -e '.[dev]'
#This includes testing tools i.e., pytest.
```
### Option 3: Install directly via GitHub URL (no clone)
```bash
pip install git+https://github.com/genie360s/pdforensic.git
```



#### 📜 License

MIT License © 2025 Alex Mkwizu
