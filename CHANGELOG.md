# Changelog

Versions follow the [`VERSION`](https://github.com/genie360s/pdforensic/blob/main/VERSION) file.

## 0.2.0

A rebuild. The earlier releases wrapped two prebuilt pdfresurrect binaries; this one is a forensic analyzer in its own right.

### Added

- `pdforensic analyze`: a full report on a PDF. Metadata (Info dictionary and XMP), hashes, encryption, digital signatures, fonts, images, features, every revision with the objects it added, modified or deleted, 27 tamper indicators each tied to a clause of the PDF standard, and how the file was produced.
- `pdforensic recover`: writes every earlier revision of an incrementally updated PDF, byte for byte.
- Python API: `analyze()`, `recover_revisions()`, `format_report()`.
- Password-protected files are read (`--password`), including those that need no password to open.
- Detection of conformance claims (PDF/A, PDF/X, PDF/UA, PDF/E, PDF/VT), XMP edit history and print-industry preflight tickets.
- Windows support, alongside Linux and macOS.
- A plain-language [user guide](https://github.com/genie360s/pdforensic/blob/main/docs/USER_GUIDE.md), technical [notes](https://github.com/genie360s/pdforensic/blob/main/docs/PDF_FORENSICS.md) and `llms.txt`.

### Changed

- **Python 3.11 or newer is required**, and [pikepdf](https://github.com/pikepdf/pikepdf) (qpdf) is now a dependency.
- pdfresurrect is built from source (`src/pdfresurrect`, v0.24b) instead of shipped as prebuilt binaries. The `pdf-meta`, `pdf-recover`, `pdf-versions` and `pdf-eof` commands and their Python functions still work.
- The version number is kept in the `VERSION` file.

### Fixed

- A PDF is no longer judged by its number of `%%EOF` markers. Linearized files and every PDF exported from Microsoft Office have two markers without ever having been edited; revisions are now counted from the file's structure.
- pdfresurrect accepts PDFs smaller than 1023 bytes.

## 0.1.x

Python wrappers and command-line tools around prebuilt pdfresurrect binaries for Linux and macOS.
