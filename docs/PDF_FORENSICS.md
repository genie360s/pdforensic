# PDF forensics: what pdforensic checks and why

Research notes behind the analyzer. Every rule cites the clause it rests on, or
is marked as a heuristic. Clause numbers refer to ISO 32000-1:2008 (PDF 1.7)
unless stated otherwise.

## Sources

| Source | Used for | Access |
|---|---|---|
| ISO 32000-1:2008 (PDF 1.7) | every clause cited below | free copy from Adobe: https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf |
| PDF Association standards index | the standards map below | https://pdfa.org/pdf-standards/ |
| pdfresurrect v0.24b source | the vendored C tool and its limits | https://github.com/enferex/pdfresurrect |
| qpdf 12 through pikepdf 10 | behaviour checked by running it | https://github.com/qpdf/qpdf |
| XMP Specification Parts 1 to 3 (Adobe; Part 1 is the text of ISO 16684-1) | Info to XMP mapping, conflict rule, history, identifiers | free, in Adobe's SDK repository: https://github.com/adobe/XMP-Toolkit-SDK/tree/main/docs |
| PDF Association XMP extension schema template | PDF/A, PDF/UA, PDF/X and PDF/VT identification namespaces and property names | https://pdfa.org/resource/xmp-extension-schema-templates/ |
| BFO PDF/A test suite (34 files, CC BY 3.0) | run as a corpus; two files vendored as fixtures | https://github.com/bfocom/pdfa-testsuite |
| Ghent PDF Output Suite 5.0: test pages, the 94 patches and their ReadMe | run locally: PDF/X-1a, X-3 and X-4, preflight tickets, signatures. Not redistributed: its legal notice limits use to "its intended purpose of testing workflow setup" | https://gwg.org/resources/ghent-pdf-output-suite/ |
| GWG "Universal Proof of Preflight" v1.0 (2008) | the preflight ticket and its signature | no longer on gwg.org; read from the Internet Archive copy of `gwg.org/wp-content/uploads/2021/05/Universalproofofpreflight.pdf` |
| Library of Congress format description of PDF/E-1 | the PDF/E identification property | https://www.loc.gov/preservation/digital/formats/fdd/fdd000495.shtml |
| PDF Association pdf-differences (Apache-2.0) and PDF 2.0 examples | version rules, unknown filters; three files vendored as fixtures | https://github.com/pdf-association/pdf-differences |
| PDF Association errata for ISO 32000-2 | "The catalog of an incremental update shall not reduce the version of the document" | https://pdf-issues.pdfa.org/32000-2-2020/clause07.html |
| veraPDF corpus (2,906 files, CC BY 4.0) | run as a corpus: PDF/A-1 to A-4, PDF/UA-1 and UA-2, Isartor | https://github.com/veraPDF/veraPDF-corpus |

Not read, because they are sold rather than published freely: ISO 19005 (PDF/A),
ISO 15930 (PDF/X), ISO 24517 (PDF/E), ISO 16612 (PDF/VT). What that leaves open
is listed under "Not verified" at the end.

`developer.adobe.com/xmp/docs/` is an overview page; the specification text
itself is the three PDFs in the SDK repository above. The Ghent Workgroup's
technical specifications (GWG 2015, GWG 2022) are available to members only
as of November 2026; its test suites and user guides are public.

### Free material worth reading next

- **ISO 32000-2:2020 (PDF 2.0)** is free from the PDF Association (since April 2023),
  bundled with ISO/TS 32001 to 32004: https://pdfa.org/resource/iso-32000-2/
  (a no-charge checkout that asks for your details).
- **ISO 14289-1 (PDF/UA-1)** is free from the PDF Association: https://pdfa.org/resource/iso-14289-pdfua/
- **PDF/A** itself is paid, but the PDF Association's Technical Notes are free:
  TN 0001 (namespaces), TN 0003 (metadata), TN 0008 (predefined XMP properties),
  TN 0010 (clarifications): https://pdfa.org/resource/iso-19005-pdfa/
- **Arlington PDF Model** (Apache-2.0): a machine-readable table of every PDF
  object and key by PDF version: https://github.com/pdf-association/arlington-pdf-model
- **veraPDF validation profiles**: machine-readable PDF/A and PDF/UA rules:
  https://github.com/veraPDF/veraPDF-validation-profiles
- **pdf-issues** (CC-BY-4.0): industry errata for the ISO texts: https://github.com/pdf-association/pdf-issues
- Older Adobe PDF References (1.3 to 1.7) and supplements: https://pdfa.org/resource/pdf-specification-index/

## Standards map

From https://pdfa.org/pdf-standards/ (read 2026-11-10).

| Name | ISO document | Based on |
|---|---|---|
| PDF 1.7 | ISO 32000-1:2008 | |
| PDF 2.0 | ISO 32000-2:2020 (the 2017 edition is withdrawn) | |
| PDF/A-1, -2, -3, -4 | ISO 19005-1:2005, -2:2011, -3:2012, -4:2020 | PDF 1.4, 1.7, 1.7, 2.0 |
| PDF/X-1a, X-3, X-4, X-5, X-6 | ISO 15930-4, -3/-6, -7, -8, -9 | PDF 1.3 to 2.0 |
| PDF/UA-1, -2 | ISO 14289-1:2014, -2:2024 | PDF 1.7, 2.0 |
| PDF/E-1 | ISO 24517-1:2008 | PDF 1.6 |
| PDF/VT-1/-2, VT-3 | ISO 16612-2:2010, -3:2020 | PDF/X-4/X-5, PDF/X-6 |
| PDF/R-1 | ISO 23504-1:2020 | PDF 1.7, 2.0 |
| XMP | ISO 16684-1:2019 | any |
| PAdES long-term signature profiles | ISO 14533-3:2017 | |

The analyzer reports a conformance **claim** when the file's XMP declares one
(`pdfaid:part`, `pdfuaid:part`, `GTS_PDFXVersion` ...). It does not validate the
claim; use veraPDF for that.

## How a PDF file records its own history

**Header (7.5.2).** `%PDF-M.m` on the first line. From PDF 1.4 the catalog's
`/Version` overrides it when later, which lets an incremental update raise the
version. Both are reported.

**Cross-reference table and trailer (7.5.4, 7.5.5).** The file ends with
`startxref`, the byte offset of the last cross-reference section, and `%%EOF`.
The trailer names the catalog (`/Root`), the information dictionary (`/Info`),
the file identifier (`/ID`) and, after an update, the previous section (`/Prev`).

**Incremental updates (7.5.6).** "Changes shall be appended to the end of the
file, leaving its original contents intact." Each update adds changed objects, a
new cross-reference section listing only those, and a new trailer with its own
`%%EOF`. Two consequences the tool is built on:

1. Cutting the file at the end of an earlier `%%EOF` gives that earlier version
   **byte for byte**. `pdforensic recover` does exactly this. It is tested against
   files MuPDF updated: the recovered revision equals the original file.
2. Comparing the cross-reference tables of consecutive revisions shows which
   objects were added, modified or deleted in each save.

**Linearization (7.5.4, Annex F).** A "fast web view" file is written with *two*
cross-reference sections, so it has two `%%EOF` markers without ever having been
updated. **Counting `%%EOF` markers therefore does not show that a file was
edited.** The linearization dictionary's `/L` is the file length when it was
linearized (Table F.1); sections within `/L` bytes are treated as one revision,
but only if `/L` lands exactly on a revision boundary, so a forged `/L` cannot
hide later revisions. A file longer than `/L` was appended to afterwards.

**Cross-reference streams and object streams (7.5.7, 7.5.8).** From PDF 1.5 the
table may be a compressed stream and most objects may sit inside compressed
object streams, invisible to byte-level searching. qpdf decodes both.

**Hybrid-reference files (7.5.8.4).** Microsoft Word, Excel and PowerPoint write
a classic table and trailer for PDF 1.4 readers, then `%%EOF`, then an *empty*
table (`xref` / `0 0`) whose trailer adds `/Prev` and `/XRefStm`, then a second
`%%EOF`. So an untouched Office export also has **two `%%EOF` markers**. The
layout was read from real Office files; in 925 local PDFs, 59 closing sections
of this kind contained no objects at all, while all 191 genuine updates did.
The rule: a section that adds no objects and whose `/XRefStm` points into the
earlier bytes belongs to the revision it closes (`structure.hybrid_reference`).
An update that only frees objects has no `/XRefStm` and still counts.

**File identifier (14.4).** `/ID` holds two strings: the first "shall not change
when the file is incrementally updated", the second changes at each update, and
"when a file is first written, both identifiers shall be set to the same value".
Different values mean the file was written again after creation.

**Information dictionary and dates (14.3.3, 7.9.4).** `Creator` is the
application that made the original document, `Producer` the one that converted
it to PDF. Dates are `D:YYYYMMDDHHmmSSOHH'mm`.

**XMP metadata (14.3.2).** A second copy of the metadata as XML. If the Info
`ModDate` is later than the XMP date stamp, "the document has likely been saved
by a writer that is not aware of metadata streams". The XMP Specification
(Part 3, 2.2.2) names the stamp: Acrobat compares Info `ModDate` with
`xmp:MetadataDate`, and "if the Info value is more recent, all the Info
dictionary entries supersede their corresponding XMP properties". Part 3,
Table 20 gives the correspondence used for every Info-against-XMP comparison:

| Info key | XMP property |
|---|---|
| Title | `dc:title` (first alternative) |
| Author | `dc:creator` (the first, or all joined by a separator) |
| Subject | `dc:description` (first alternative) |
| Keywords | `pdf:Keywords` |
| Creator | `xmp:CreatorTool` |
| Producer | `pdf:Producer` |
| CreationDate, ModDate | `xmp:CreateDate`, `xmp:ModifyDate` |
| Trapped | `pdf:Trapped` |

When the stale XMP still names a different producer than the Info dictionary,
it shows what the document was before it was re-saved. In real files this is
typically Info "macOS Quartz PDFContext" over XMP "Microsoft Word" or "Adobe
PDF Library" dated years earlier.

**XMP history (XMP Specification Part 2, 1.2.4).** `xmpMM:History` is an ordered
list of events, each with an action (`created`, `converted`, `saved`, `edited`
...), a time and usually the software that performed it. It is reported as
`xmp_history`, and the software it names is added to the provenance evidence.
`xmpMM:DocumentID` is common to all versions of a document; `xmpMM:InstanceID`
identifies one saved incarnation (Part 1).

**Preflight ticket (GWG Universal Proof of Preflight).** Print workflows record
a preflight check in XMP under `http://www.gwg.org/ns/gwg_preflight_v1/`:
profile name, the software and version that made the profile, the result
(`Errors`, `Warnings`, `Info` or `Success`), the time it ran and a profile
fingerprint. "For protection against tampering with both the PDF itself as well
as the audit trail", the file is then signed with a signature whose Name is
exactly "Preflight Ticket Signature". The report shows the ticket as
`preflight_ticket`, says whether that signature is present, and whether it still
covers the whole file. Other workflow metadata seen next to it (Enfocus
Certified PDF `CP2:` sessions, GWG ad tickets) is listed under `xmp` as found
and not interpreted, because their specifications were not read.

**PDF version over time (7.5.2, 7.5.6).** The header gives the version; the
catalog's `/Version` can raise it, in the original file or in an update, and
"the catalog of an incremental update shall not reduce the version" (ISO 32000-2
errata). Each revision's catalog version is reported. Only 1.0 to 1.7 and 2.0
were ever published; anything else is flagged rather than given a name.

**Filters (7.4, Table 6).** The standard defines ten stream filters. A stream
that names any other filter cannot be decoded, so whatever it holds cannot be
inspected; such streams are counted in `structure.nonstandard_filters`.
`/Filter` in a signature or encryption dictionary names a handler and is not
counted.

**Custom Info keys in XMP (Part 3, 2.2.1).** User-defined Info keys are mirrored
in the `pdfx:` namespace with characters that cannot appear in an XML name
written as U+2182 plus four hexadecimal digits; they are decoded for display.

**Encryption (7.6).** Strings and streams are encrypted; names, numbers and the
cross-reference data are not. Many "protected" files have an owner password
only and an empty user password, and open without any password; qpdf decrypts
those, and files with a user password when it is supplied.

**Signatures (12.8.1).** `/ByteRange` lists the bytes the digest covers: the
whole file except the signature value. Signing is itself an incremental save,
and "if a signed document is modified and saved by incremental update, the data
corresponding to the byte range of the original signature is preserved", so the
signed state stays recoverable and anything after the signed range is later.

## Tamper indicators

Severity is `info`, `low`, `medium` or `high`; the report's `level` is the
highest one present. An indicator is evidence with its detail attached, not a
verdict.

| id | Severity | Meaning | Basis |
|---|---|---|---|
| `incremental_updates` | medium (info if every update is sealed by a signature or only stores validation data) | saved again after first being written | 7.5.6 |
| `id_mismatch` | low | `/ID` strings differ | 14.4 |
| `permanent_id_changed` | medium | first `/ID` string differs between revisions | 14.4 |
| `dates_differ` | low (info up to 5 s) | `ModDate` later than `CreationDate` | 14.3.3 |
| `moddate_before_creation` | low (info up to 60 s) | `ModDate` earlier than `CreationDate`; Canva writes it a few seconds early on every export | 14.3.3 |
| `future_date` | low | a date lies in the future | heuristic |
| `info_xmp_mismatch` | low for Producer, Creator and dates; info for Title, Author, Subject, Keywords, Trapped | Info and XMP disagree | XMP Spec Part 3, Table 20 |
| `info_newer_than_xmp` | medium (info when the gap is a whole number of hours: a time-zone slip) | Info `ModDate` is more than a minute later than `xmp:MetadataDate`: saved again by software that does not maintain XMP | 14.3.2; XMP Spec Part 3, 2.2.2 |
| `xmp_history` | info | the XMP lists the events of the file's own history | XMP Spec Part 2, 1.2.4 |
| `preflight_ticket` | info | a preflight check is recorded: profile, software, result, time | GWG Universal Proof of Preflight |
| `preflight_ticket_unsealed` | low | a ticket is present without its "Preflight Ticket Signature" | GWG Universal Proof of Preflight |
| `unknown_pdf_version` | low | the declared version was never published | 7.5.2; ISO 32000-2 |
| `version_downgraded` | low | an update's catalog lowers the PDF version | ISO 32000-2 7.5.6 errata |
| `nonstandard_filter` | low | a stream uses a filter the standard does not define | 7.4, Table 6 |
| `tool_changed_between_revisions` | medium | `Producer` or `Creator` differs between revisions | 14.3.3 |
| `content_after_signature` | high; low if every later revision is sealed by a further signature (none is verified here); info if only validation data was added | bytes follow the signed range | 12.8.1 |
| `signature_byte_range_unusual` | medium | `/ByteRange` is not "0 to gap, gap to revision end" | 12.8.1 |
| `signature_removed` | high | a signature dictionary is in the file but no longer referenced | heuristic |
| `trailing_data` | low | bytes after the final `%%EOF` | 7.5.5 |
| `xref_offset_mismatch` | medium | a cross-reference entry does not point at its object (entries at offset 0, which macOS Quartz writes for unused numbers, are ignored) | 7.5.4 |
| `xref_unreadable` | medium | a revision's `startxref` leads nowhere | 7.5.4 |
| `structural_damage` | medium | qpdf had to rebuild the cross-reference data | qpdf diagnostics |
| `syntax_warnings` | info | small syntax faults readers tolerate (wrong stream length, odd line endings); says something about the writer, not about a later change | qpdf diagnostics |
| `unreferenced_objects` | low | objects no cross-reference section points to | 7.5.4 |
| `deleted_objects` | low | objects freed in a later revision (data still present) | 7.5.4, 7.5.6 |
| `linearization_stale` | info | file is longer than its linearization length | Table F.1 |
| `editing_tool_named` | info | metadata names a PDF editing tool | heuristic |

A revision counts as storing only validation data when it adds objects, one of
them the `/DSS`, and modifies nothing but the catalog, the Info dictionary and
the XMP stream, with every existing catalog entry (the page tree included)
left as it was. A looser test would let a token `/DSS` object excuse a real
edit made after signing.

What the indicators cannot show:

- **A clean report is not proof of authenticity.** "Save As", "Print to PDF", or
  any tool that rewrites the whole file produces a new single-revision file with
  no history. Only the metadata then hints at it (dates, Producer).
- **`id_mismatch` and `dates_differ` are common in honest files.** Any optimiser,
  encryption step or linearizer rewrites the file after creation. Adobe's own
  copy of ISO 32000-1 shows both. In 925 ordinary PDFs on one machine, 30% had
  `id_mismatch`, 23% `dates_differ`, 16% `syntax_warnings`, and 5% a genuine
  incremental update; 47% had no indicator and 7% reached `medium`.
- **`unreferenced_objects` often means post-processing, not concealment.** Tools
  that stamp, sign or re-save in place (seen with PDF Expert, PDFlib PLOP,
  LiveCycle Designer) leave the superseded copy of an object behind.
- **Signature cryptography is not checked.** The tool reports what the byte
  range covers, not whether the signature verifies or who signed.
- Metadata is editable. Producer and Creator say what the file claims.

## Provenance: how was the file made?

Three independent observations are reported side by side.

1. **Tools named in the metadata**: `Creator`, `Producer`, `xmp:CreatorTool` and
   `pdf:Producer` are matched against a table of known software. Each match is
   listed with the field and the exact string it matched.
2. **Origin and generation**: the category of the first authoring match, e.g.
   `spreadsheet` / `exported_from_application` for Excel, `library` /
   `programmatic` for ReportLab or iText (typical of system-generated documents),
   `html_renderer` for headless Chrome or wkhtmltopdf, `os_print` for macOS
   Quartz or Microsoft Print to PDF.
3. **Content profile**, from the pages themselves: `text`, `image_only` (every
   page is an image with no text: a scan or an image converted to PDF),
   `image_with_hidden_text` (an image under invisible text, which is what OCR
   writes), or `mixed`.

Limits: **CSV has no signature of its own.** A CSV reaches PDF through a
spreadsheet or a library, and the file shows that tool. The same holds for any
source format: the PDF records the last converter, not the original file type.
The tool table is a heuristic and can be extended in `forensics.py` (`_TOOLS`).

## Engine and speed

Object-level work is done by qpdf (C++) through pikepdf; the raw byte layer in
`_pdf.py` supplies what PDF libraries hide (revision boundaries, physical object
headers, raw trailers). Measured on Adobe's ISO 32000-1 PDF (22 MB, 126,988
objects, 756 pages, RC4-encrypted) on an Apple Silicon Mac:

| Implementation | Time |
|---|---|
| First pure-Python version of this analyzer | 4.5 s |
| lopdf 0.47 (Rust), load only (parses every object) | 0.21 to 0.24 s |
| qpdf 12, open only (lazy) | 0.02 to 0.04 s |
| qpdf 12, forced to parse every object, no analysis | 0.33 to 0.63 s |
| **Current analyzer (qpdf + raw scan), full report** | **0.4 to 0.5 s** |
| Current analyzer on small documents (1 to 3 KB) | about 0.5 ms |

On 925 real PDFs (3.1 GB in total): median 6.5 ms, 95th percentile 111 ms,
slowest 0.9 s (a file with 34 revisions, each opened to compare).

qpdf was chosen over a Rust core because it parses lazily (only the objects the
analysis touches), handles every encryption revision and damaged files, exposes
the cross-reference table, and ships prebuilt wheels for all three platforms.
Cost grows with the number of objects, revisions and pages, not with file size:
a 59 MB scan of 707 pages takes 0.28 s. Three things keep it low: objects are
found by scanning raw bytes for a few keys instead of visiting each one through
the binding; only the images a page actually paints are looked at; and when a
file has more than 3000 link, image or attachment objects they are counted from
the byte hits (`features.counts_estimated` is then true).

## Not verified

- No identification name rests on memory any more. PDF/A (`pdfaid:part`,
  `conformance`), PDF/UA (`pdfuaid:part`), PDF/X (`pdfxid:GTS_PDFXVersion`) and
  PDF/VT (`pdfvtid:GTS_PDFVTVersion`) are confirmed by the PDF Association
  template; PDF/E (`pdfe:ISO_PDFEVersion` with the value `PDF/E-1`) by the
  Library of Congress description of ISO 24517-1. Detection is confirmed on
  real files for PDF/A-1a/1b/2a/2b/2u/3b/4/4e/4f, PDF/UA-1/2 and
  PDF/X-1a/3/4. No real PDF/E or PDF/VT file was available to test.
- The ISO texts of PDF/A, PDF/X, PDF/E and PDF/VT themselves were not read.
- Whether a PDF/A, PDF/X or PDF/UA claim is *true* is not checked here at all.
- That a signature's `/Contents` is exempt from encryption is not relied on.
- The release workflow has not run yet (it runs on a version tag), and nothing
  was built or tested on Intel macOS, for which pikepdf ships no wheel.

## What was run

| Check | Where | Result |
|---|---|---|
| 236 unit, integration, regression and fuzz tests | macOS arm64, Python 3.14 | pass |
| Same suite, installed with `uv sync`, C tool built by the install hook | Linux arm64, Python 3.11 (Docker) | pass |
| Same suite | Linux x86_64, Python 3.13 (Docker) | pass |
| `CMakeLists.txt` build, sdist, wheel, lint | macOS and both Linux containers | pass |
| `manylinux` wheels with cibuildwheel and the uv build frontend, release settings | x86_64 and arm64 | built, repaired, tested |
| Code review and an over-engineering review of the whole change | | 12 + 12 findings, each fixed with a regression test (`tests/test_review.py`) |
| C tool cross-compiled with MinGW-w64, run under Wine | Windows x86_64 target | builds; `-q`, `-w` and backslash paths work |
| GitHub Actions CI: lint, suite, CMake build, packaging | Ubuntu, macOS and Windows (MSVC 19.51), Python 3.11 and 3.13 | all 11 jobs pass; 235 tests on Windows, where a file name containing ":" cannot be created |
| Fuzzing: 300,000 damaged inputs, 12 seeds | macOS | no crash, no hang |
| 932 real PDFs, page counts compared with qpdf | macOS | no crash, no disagreement |
| BFO PDF/A test suite, 34 files | macOS | no crash; PDF/A part and level read correctly on every file |
| Ghent PDF Output Suite 5.0, 4 test pages and 94 patches | macOS | PDF/X-1a, X-3 and X-4 read; three preflight tickets found sealed; the 26 files without a claim are ReadMes and reports |
| veraPDF corpus, 2,906 files | macOS | no crash; the claim matches the folder except in files built to declare something invalid |
| PDF Association pdf-differences (37) and PDF 2.0 examples (7) | macOS | no crash; all three version files reported as 1.6, as their documentation requires |
