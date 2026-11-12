"""Forensic report for a PDF file: metadata, revision history, tamper
indicators and provenance.

Object-level work (parsing, decoding, decryption) is done by qpdf through
pikepdf; the revision history comes from the raw bytes (see _pdf.py).
Section numbers refer to ISO 32000-1:2008 (PDF 1.7). Everything reported
under "tamper" and "provenance" is an indicator with its evidence attached,
never a proof: a full re-save or a print-to-PDF pass erases a file's history.
"""

from __future__ import annotations

import bisect
import hashlib
import io
import os
import re
import xml.etree.ElementTree as ET
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pikepdf

from ._pdf import _NOT_REGULAR, WS, PdfError, RawPdf, Ref, Stream, parse_indirect, skip_ws, unescape_name
from ._version import __version__

__all__ = ["analyze", "recover_revisions", "format_report", "PdfError"]

# ---- dates -------------------------------------------------------------------

_PDF_DATE = re.compile(  # 7.9.4: D:YYYYMMDDHHmmSSOHH'mm
    r"^\s*(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?\s*(?:([Zz])|([+-])(\d{2})'?(\d{2})?'?)?")
_ISO_DATE = re.compile(  # XMP dates (ISO 8601 profile)
    r"^\s*(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?\s*"
    r"(?:([Zz])|([+-])(\d{2}):?(\d{2})?)?\s*$")


def parse_date(value):
    """Parse a PDF date or an XMP date. Returns a datetime (timezone-aware
    when the string carries an offset) or None."""
    if not isinstance(value, str):
        return None
    m = _PDF_DATE.match(value) if re.match(r"\s*(D:|\d{8})", value) else _ISO_DATE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s, z, sign, oh, om = m.groups()
    try:
        tz = None
        if z:
            tz = timezone.utc
        elif sign:
            delta = timedelta(hours=int(oh), minutes=int(om or 0))
            tz = timezone(-delta if sign == "-" else delta)
        return datetime(int(y), int(mo or 1), int(d or 1), int(h or 0), int(mi or 0), int(s or 0), tzinfo=tz)
    except (ValueError, OverflowError):
        return None


def _iso(value):
    d = parse_date(value)
    return d.isoformat() if d else None


def _squash(text):
    return " ".join(text.split())


def _same_time(a, b):
    if a.tzinfo and b.tzinfo:
        return a == b
    return a.replace(tzinfo=None) == b.replace(tzinfo=None)


def _later(a, b):
    """a - b in seconds, or None when one has a UTC offset and the other does not."""
    if bool(a.tzinfo) != bool(b.tzinfo):
        return None
    return (a - b).total_seconds()


# ---- XMP ---------------------------------------------------------------------

_RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
_XML = "{http://www.w3.org/XML/1998/namespace}"
NS_DC = "http://purl.org/dc/elements/1.1/"
NS_XMP = "http://ns.adobe.com/xap/1.0/"
NS_PDF = "http://ns.adobe.com/pdf/1.3/"
NS_PDFX = "http://ns.adobe.com/pdfx/1.3/"
NS_XMP_MM = "http://ns.adobe.com/xap/1.0/mm/"
NS_GWG_PREFLIGHT = "http://www.gwg.org/ns/gwg_preflight_v1/"
PREFLIGHT_SIGNER = "Preflight Ticket Signature"
NS_PDFA_ID = "http://www.aiim.org/pdfa/ns/id/"
NS_PDFUA_ID = "http://www.aiim.org/pdfua/ns/id/"


def parse_xmp(xml):
    """Parse an XMP packet into {(namespace URI, local name): (display key, value)}."""
    if xml[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in xml[:8]:  # UTF-16, with or without a byte-order mark
        codec = "utf-16" if xml[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-16-be" if xml[:1] == b"\x00" else "utf-16-le"
        text = xml.decode(codec, "replace")
        xml = re.sub(r"""^(\s*<\?xml[^>]*?)\s+encoding=["'][^"']*["']""", r"\1", text).encode("utf-8")
    if b"<!DOCTYPE" in xml or b"<!ENTITY" in xml:
        raise PdfError("XMP packet declares a DTD or entities; not parsed")
    prefixes, root = {}, None
    try:
        for event, item in ET.iterparse(io.BytesIO(xml.strip(WS)), events=("start-ns", "start")):
            if event == "start-ns":
                prefixes.setdefault(item[1], item[0])
            elif root is None:
                root = item
    except ET.ParseError as exc:
        raise PdfError("XMP packet is not well-formed XML: %s" % exc) from None

    def split(tag):
        uri, _, local = tag[1:].partition("}") if tag.startswith("{") else ("", "", tag)
        if uri == NS_PDFX:  # custom Info keys: U+2182 plus four hex digits stands for one character
            local = re.sub("\u2182([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), local)
        prefix = prefixes.get(uri)
        return uri, local, "%s:%s" % (prefix, local) if prefix else tag

    def fields(el):
        out = {split(k)[2]: v for k, v in el.attrib.items() if not k.startswith((_RDF, _XML))}
        out.update((split(k.tag)[2], value(k)) for k in el if not k.tag.startswith(_RDF))
        return out

    def value(el):
        for kind in ("Alt", "Seq", "Bag"):
            box = el.find(_RDF + kind)
            if box is not None:
                return [value(li) for li in box.findall(_RDF + "li")]
        inner = el.find(_RDF + "Description")
        struct = fields(inner if inner is not None else el)
        return struct if struct else (el.text or "").strip()

    out = {}
    rdf = root if root is not None and root.tag == _RDF + "RDF" else (
        root.find(".//" + _RDF + "RDF") if root is not None else None)
    for desc in rdf.findall(_RDF + "Description") if rdf is not None else []:
        for k, v in desc.attrib.items():
            if not k.startswith((_RDF, _XML)):
                uri, local, key = split(k)
                out[(uri, local)] = (key, v)
        for child in desc:
            uri, local, key = split(child.tag)
            out[(uri, local)] = (key, value(child))
    return out


def _history(xmp):
    """xmpMM:History as plain records. Each ResourceEvent has an action
    (created, converted, saved, edited ...), a time and usually the software
    that performed it (XMP Specification Part 2, 1.2.4)."""
    events = xmp.get((NS_XMP_MM, "History"), (None, None))[1]
    out = []
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        f = {k.rsplit("}", 1)[-1].rsplit(":", 1)[-1]: v for k, v in event.items() if isinstance(v, str)}
        out.append({"action": f.get("action"), "when": f.get("when"), "software_agent": f.get("softwareAgent"),
                    "changed": f.get("changed"), "parameters": f.get("parameters")})
    return out


def _preflight(xmp, signatures):
    """The GWG preflight ticket, if the file carries one.

    GWG "Universal Proof of Preflight" (2008): the result of a preflight check
    is stored in XMP under its own namespace and sealed by a signature whose
    Name is exactly "Preflight Ticket Signature", applied after the ticket is
    written, so that neither the PDF nor the ticket can change unnoticed."""
    fields = {local: _first(value) for (uri, local), (_, value) in xmp.items() if uri == NS_GWG_PREFLIGHT}
    if not fields:
        return None
    seal = next((s for s in signatures if s.get("signer_name") == PREFLIGHT_SIGNER and s["live"]), None)
    return {
        "profile_name": fields.get("profile_name"),
        "profile_creator": fields.get("profile_creator"),
        "profile_creator_version": fields.get("profile_creator_version"),
        "profile_format_version": fields.get("profile_format_version"),
        "results": fields.get("preflight_results"),
        "results_description": fields.get("preflight_results_description"),
        "executed_date": fields.get("preflight_executed_date"),
        "profile_fingerprint": fields.get("profile_fingerprint"),
        "signed": seal is not None,
        "signature_covers_whole_file": seal.get("covers_whole_file") if seal else None,
    }


def _xmp_value(xmp, uri, local):
    """The first plain string of the XMP property (uri, local), or None."""
    return _first(xmp.get((uri, local), (None, None))[1])


def _first(value):
    """The first plain string of an XMP value (language alternatives, lists)."""
    while isinstance(value, list) and value:
        value = value[0]
    return value if isinstance(value, str) else None


# ---- provenance table ----------------------------------------------------------

# Substring patterns matched against Creator / Producer / xmp:CreatorTool /
# pdf:Producer. A match is reported with the string it matched; it states
# what the file says about itself, and those fields can be edited.
_TOOLS = [(re.compile(p, re.I), tool, cat) for p, tool, cat in [
    (r"Microsoft.{0,4}Excel|\bExcel\b", "Microsoft Excel", "spreadsheet"),
    (r"^Calc$", "LibreOffice/OpenOffice Calc", "spreadsheet"),
    (r"^Numbers$", "Apple Numbers", "spreadsheet"),
    (r"Google Sheets", "Google Sheets", "spreadsheet"),
    (r"Microsoft.{0,4}Word|\bWord\b", "Microsoft Word", "word_processor"),
    (r"^Writer$", "LibreOffice/OpenOffice Writer", "word_processor"),
    (r"^Pages$", "Apple Pages", "word_processor"),
    (r"Google Docs", "Google Docs", "word_processor"),
    (r"WPS Writer", "WPS Office Writer", "word_processor"),
    (r"PowerPoint", "Microsoft PowerPoint", "presentation"),
    (r"^Impress$", "LibreOffice/OpenOffice Impress", "presentation"),
    (r"^Keynote$", "Apple Keynote", "presentation"),
    (r"LibreOffice|OpenOffice", "LibreOffice/OpenOffice PDF export", "office_suite"),
    (r"InDesign", "Adobe InDesign", "design"),
    (r"FrameMaker", "Adobe FrameMaker", "design"),
    (r"LiveCycle Designer", "Adobe LiveCycle Designer (forms)", "design"),
    (r"Illustrator", "Adobe Illustrator", "design"),
    (r"Photoshop", "Adobe Photoshop", "design"),
    (r"\bCanva\b", "Canva", "design"),
    (r"Scribus", "Scribus", "design"),
    (r"CorelDRAW", "CorelDRAW", "design"),
    (r"QuarkXPress", "QuarkXPress", "design"),
    (r"Inkscape", "Inkscape", "design"),
    (r"Affinity", "Affinity", "design"),
    (r"pdfTeX|LaTeX|XeTeX|xdvipdfmx|LuaTeX|dvips|\bTeX\b", "TeX typesetting system", "typesetting"),
    (r"Typst", "Typst", "typesetting"),
    (r"HeadlessChrome", "headless Chrome (automated HTML to PDF)", "html_renderer"),
    (r"wkhtmltopdf", "wkhtmltopdf (HTML to PDF)", "html_renderer"),
    (r"WeasyPrint", "WeasyPrint (HTML to PDF)", "html_renderer"),
    (r"\bPrince\b", "Prince (HTML to PDF)", "html_renderer"),
    (r"dompdf", "dompdf (HTML to PDF)", "html_renderer"),
    (r"openhtmltopdf", "openhtmltopdf (HTML to PDF)", "html_renderer"),
    (r"Skia/PDF", "Chromium Skia PDF backend (Chrome, Edge, Electron)", "browser"),
    (r"Chromium|Chrome", "Chromium-based browser", "browser"),
    (r"PDFium", "PDFium (the PDF engine in Chromium browsers)", "browser"),
    (r"ReportLab", "ReportLab (Python library)", "library"),
    (r"iText", "iText (Java/.NET library)", "library"),
    (r"FPDF|fpdf2", "FPDF family (PHP/Python library)", "library"),
    (r"TCPDF", "TCPDF (PHP library)", "library"),
    (r"\bmPDF\b", "mPDF (PHP library)", "library"),
    (r"pdf-lib", "pdf-lib (JavaScript library)", "library"),
    (r"jsPDF", "jsPDF (JavaScript library)", "library"),
    (r"pdfmake", "pdfmake (JavaScript library)", "library"),
    (r"PDFKit", "PDFKit", "library"),
    (r"PDFsharp|MigraDoc", "PDFsharp/MigraDoc (.NET library)", "library"),
    (r"PDFBox", "Apache PDFBox (Java library)", "library"),
    (r"Apache FOP", "Apache FOP (XSL-FO)", "library"),
    (r"\bPrawn\b", "Prawn (Ruby library)", "library"),
    (r"QuestPDF", "QuestPDF (.NET library)", "library"),
    (r"OpenPDF", "OpenPDF (Java library)", "library"),
    (r"PDFlib", "PDFlib", "library"),
    (r"Aspose", "Aspose", "library"),
    (r"3-Heights", "3-Heights PDF tools", "library"),
    (r"react-pdf", "react-pdf (JavaScript library)", "library"),
    (r"Telerik", "Telerik document processing", "library"),
    (r"Syncfusion", "Syncfusion", "library"),
    (r"libHaru|Haru Free PDF", "libHaru (C library)", "library"),
    (r"\bcairo\b", "cairo graphics library", "library"),
    (r"\bQt\b", "Qt PDF engine", "library"),
    (r"JasperReports", "JasperReports", "report_engine"),
    (r"Stimulsoft", "Stimulsoft Reports", "report_engine"),
    (r"Oracle.{0,12}Reports|Oracle PDF driver", "Oracle Reports", "report_engine"),
    (r"Crystal Reports", "Crystal Reports", "report_engine"),
    (r"Reporting Services", "Microsoft SQL Server Reporting Services", "report_engine"),
    (r"BI Publisher", "Oracle BI Publisher", "report_engine"),
    (r"Quartz PDFContext", "macOS Quartz PDFContext (Print to PDF, Preview)", "os_print"),
    (r"Microsoft: Print To PDF", "Microsoft Print to PDF", "os_print"),
    (r"PScript5", "Windows PostScript printer driver", "os_print"),
    (r"cups-pdf|CUPS", "CUPS PDF printing", "os_print"),
    (r"PDFCreator|CutePDF|doPDF|Bullzip|PrimoPDF", "virtual PDF printer", "os_print"),
    (r"Acrobat Distiller", "Adobe Acrobat Distiller (PostScript to PDF)", "converter"),
    (r"\bcalibre\b", "calibre (e-book converter)", "converter"),
    (r"PDFMaker", "Adobe PDFMaker (Office add-in)", "converter"),
    (r"Ghostscript", "Ghostscript", "converter"),
    (r"Adobe PDF Library", "Adobe PDF Library", "library"),
    (r"img2pdf", "img2pdf (images to PDF)", "image_tool"),
    (r"ImageMagick", "ImageMagick", "image_tool"),
    (r"\bPIL\b|Pillow", "Pillow (Python imaging)", "image_tool"),
    (r"Adobe Scan|CamScanner|intsig\.com|ScanSnap|NAPS2|Simple Scan|Genius Scan|Scanner Pro|Office Lens",
     "scanning app", "scan_capture"),
    (r"\b(Canon|EPSON|Xerox|RICOH|KONICA MINOLTA|Kyocera|Brother|Lexmark|SHARP|TOSHIBA|HP Scan)\b",
     "scanner or multifunction device", "scan_capture"),
    (r"Paper Capture|ABBYY|Tesseract|OCRmyPDF|\bOCR\b", "OCR software", "ocr"),
    (r"Acrobat(?! Distiller| PDFMaker)", "Adobe Acrobat", "editor"),
    (r"Foxit", "Foxit", "editor"),
    (r"\bNitro\b", "Nitro PDF", "editor"),
    (r"PDF-XChange", "PDF-XChange", "editor"),
    (r"PDFelement|Wondershare", "Wondershare PDFelement", "editor"),
    (r"iLovePDF|Smallpdf|Sejda|PDFescape|Soda PDF|PDF24|PDFsam|Xodo|PDF Expert|Master PDF",
     "PDF editing service or tool", "editor"),
    (r"pdftk|qpdf|pikepdf|pypdf|PyPDF2|PyMuPDF|MuPDF|pdfcpu|(?-i:\bcpdf\b)", "PDF manipulation library or tool", "editor"),
    (r"DocuSign|Adobe Sign|EchoSign|HelloSign|Dropbox Sign", "e-signature service", "esign"),
]]

_GENERATION = {
    "spreadsheet": "exported_from_application", "word_processor": "exported_from_application",
    "presentation": "exported_from_application", "office_suite": "exported_from_application",
    "design": "exported_from_application", "typesetting": "exported_from_application",
    "html_renderer": "programmatic", "library": "programmatic", "report_engine": "programmatic",
    "browser": "browser_print", "os_print": "print_to_pdf", "converter": "print_to_pdf",
    "image_tool": "image_conversion", "scan_capture": "scan", "ocr": "scan",
    "editor": "post_processed", "esign": "post_processed",
}
_ANNOTS = {"Text", "Link", "FreeText", "Line", "Square", "Circle", "Polygon", "PolyLine", "Highlight",
           "Underline", "Squiggly", "StrikeOut", "Stamp", "Caret", "Ink", "Popup", "FileAttachment",
           "Sound", "Movie", "Widget", "Screen", "PrinterMark", "TrapNet", "Watermark", "3D", "Redact"}
# Published PDF versions: 1.0 to 1.7 (ISO 32000-1 7.5.2) and 2.0 (ISO 32000-2).
_SPECS = {**{"1.%d" % n: "Adobe PDF Reference (PDF 1.%d)" % n for n in range(7)},
          "1.7": "ISO 32000-1:2008", "2.0": "ISO 32000-2:2020"}
# 7.4, Table 6: the standard stream filters.
_STANDARD_FILTERS = {b"ASCIIHexDecode", b"ASCII85Decode", b"LZWDecode", b"FlateDecode", b"RunLengthDecode",
                     b"CCITTFaxDecode", b"JBIG2Decode", b"DCTDecode", b"JPXDecode", b"Crypt"}
_SEVERITY = ["none", "info", "low", "medium", "high"]
# qpdf messages that mean the cross-reference data was wrong and had to be rebuilt.
_DAMAGE = re.compile(r"damaged|reconstruct|expected \d+ \d+ obj|not found in file|xref not found"
                     r"|can't find startxref|unable to find|could not open")

# ---- helpers ---------------------------------------------------------------------

_DICT = (pikepdf.Dictionary, pikepdf.Stream)
_QPDF_ERRORS = (pikepdf.PdfError, pikepdf.PasswordError, RuntimeError)
_SNIFF = 1 << 20  # bytes of page content examined for text operators
_Wb = rb"(?:[\x00\t\n\x0c\r ]|%[^\r\n]*)*"  # white space and comments between two tokens (7.2.3)

# Dictionary entries that mark an object for a precise look. The last
# alternative catches names written with #xx escapes (7.3.5), so a key
# obfuscated as /J#53 is not missed; _hits() decodes those before deciding.
_KEYS = re.compile(
    rb"/(?:ByteRange|JS|Type" + _Wb + rb"/(?:Font|EmbeddedFile)|Subtype" + _Wb + rb"/Image"
    rb"|S" + _Wb + rb"/(?:JavaScript|Launch|URI|SubmitForm|ImportData|GoToR|GoToE)"
    rb")(?![A-Za-z0-9])|/[A-Za-z0-9]*#[0-9A-Fa-f]{2}[A-Za-z0-9#]*")
_KEY_NAMES = {b"ByteRange", b"JS", b"Font", b"EmbeddedFile", b"Image",
              b"JavaScript", b"Launch", b"URI", b"SubmitForm", b"ImportData", b"GoToR", b"GoToE"}
_REMOTE = (b"SubmitForm", b"ImportData", b"GoToR", b"GoToE")
_DEEP = {b"Font", b"ByteRange", b"#"}  # objects that are always opened and walked in full
_EXACT_LIMIT = 3000  # above this many other objects, actions and images are counted from the byte hits
# End of a stream's dictionary. One ">" is accepted: readers tolerate a dictionary closed that way.
_STREAM_START = re.compile(rb">[\x00\t\n\x0c\r ]*stream[\r\n]")
_FILTER_NAME = re.compile(rb"/([^\x00\t\n\x0c\r ()<>\[\]{}/%]+)")
_FILTER = re.compile(rb"/Filter" + _Wb + rb"(?:" + _FILTER_NAME.pattern + rb"|\[((?:" + _Wb + _FILTER_NAME.pattern.replace(
    b"(", b"(?:", 1) + rb")*)" + _Wb + rb"\])")
_BYTE_RANGE = re.compile(
    rb"/ByteRange" + _Wb + rb"\[" + _Wb + rb"(\d{1,20})\s+(\d{1,20})\s+(\d{1,20})\s+(\d{1,20})" + _Wb + rb"\]")


def _hits(buffer, start=0):
    """(offset, kind) for every key of interest; kind is the name that
    matched, or b"#" for an escaped name that decodes to one of them."""
    for m in _KEYS.finditer(buffer, start):
        name = m.group()
        if b"#" in name:
            if unescape_name(name[1:]) in _KEY_NAMES:
                yield m.start(), b"#"
        else:
            yield m.start(), name.rsplit(b"/", 1)[1]


def _byte_ranges(data):
    at = data.find(b"/ByteRange")
    while at >= 0:
        m = _BYTE_RANGE.match(data, at)
        if m:
            yield m
        at = data.find(b"/ByteRange", at + 10)


def _read(source):
    if isinstance(source, (bytes, bytearray)):
        return bytes(source), None
    with open(source, "rb") as f:
        return f.read(), os.fspath(source)


def _open(data, password):
    return pikepdf.open(io.BytesIO(data), password=password)


def _plain(message):
    """A qpdf message without the "stream <...>:" prefix that names the input."""
    return re.sub(r"^stream <[^>]*>:? ?", "", str(message))


def _qpdf_warnings(pdf):
    """Problems qpdf met so far (the call drains qpdf's list)."""
    return [_plain(w) for w in pdf.get_warnings()]


def _table(pdf, raw):
    """qpdf's merged cross-reference table as {(num, gen): key}, and the
    entries that point at nothing. key is the offset of the object's header,
    or (object stream number, index) for an object in an object stream (7.5.7).

    Offsets are corrected here to where the header really is, because an entry
    may point at white space before it or be relative to a header that does
    not start the file; every later comparison can then be exact."""
    out, bad = {}, []
    for objgen, e in pdf.get_xref_table().items():
        if e.type == 2:
            out[objgen] = (e.obj_stream_number, e.obj_stream_index)
        elif e.type == 1 and e.offset:
            # An in-use entry at offset 0 is not an object (the header is
            # there); macOS Quartz writes such entries for unused numbers.
            at = e.offset if raw.header_at.get(e.offset) == objgen else _locate(raw, objgen, e.offset)
            if at is None:
                bad.append((objgen[0], e.offset))
            out[objgen] = e.offset if at is None else at
    return out, bad


def _load(data, password):
    """Raw structure plus a qpdf handle on the last revision (None if qpdf cannot open it)."""
    raw = RawPdf(data)
    pdf = table = error = None
    bad, locked = [], False
    try:
        pdf = _open(data, password)
        table, bad = _table(pdf, raw)
    except pikepdf.PasswordError:
        locked, error = True, "a password is required to open the file"
    except _QPDF_ERRORS as exc:
        error = _plain(exc)
    raw.build_revisions(sorted(v for v in table.values() if isinstance(v, int)) if table else ())
    return raw, pdf, table, bad, locked, error


def _nm(value):
    """A PDF name as a plain string without the slash, else None."""
    if not isinstance(value, pikepdf.Name):
        return None
    try:
        return str(value)[1:]
    except UnicodeDecodeError:  # a name whose bytes are not UTF-8: show its written form
        return value.unparse().decode("latin-1")[1:]


def _key(name):
    """A dictionary key as printable text (keys may hold undecodable bytes)."""
    return name[1:].encode("utf-8", "replace").decode("utf-8")


def _num(value):
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else float(value) if isinstance(value, Decimal) else None


def _walk(obj, depth=0):
    """Yield the dictionaries stored directly inside an object; indirect
    references are not followed."""
    if isinstance(obj, _DICT):
        yield obj
        children = [v for _, v in obj.items()] if depth < 12 else ()
    elif isinstance(obj, pikepdf.Array) and depth < 12:
        children = obj
    else:
        return
    for v in children:
        if isinstance(v, pikepdf.Object) and not v.is_indirect:
            yield from _walk(v, depth + 1)


def _label(obj):
    if isinstance(obj, _DICT):
        kind, sub = _nm(obj.get("/Type")), _nm(obj.get("/Subtype"))
        sub = "/" + sub if sub else ""
        if kind:
            return kind + sub
        if "/ByteRange" in obj:
            return "Sig"
        return ("Stream" if isinstance(obj, pikepdf.Stream) else "Dictionary") + sub
    if isinstance(obj, pikepdf.Array):
        return "Array"
    if isinstance(obj, pikepdf.String):
        return "String"
    if isinstance(obj, pikepdf.Name):
        return "Name"
    return {bool: "Boolean", int: "Integer", type(None): "Null"}.get(type(obj), "Real")


def _info(pdf):
    """The document information dictionary (14.3.3) as plain values."""
    try:
        d = pdf.trailer.get("/Info")
        if not isinstance(d, pikepdf.Dictionary):
            return None
        out = {}
        for k, v in sorted(d.items(), key=lambda item: _key(item[0])):
            if isinstance(v, pikepdf.String):
                out[_key(k)] = str(v)
            elif isinstance(v, pikepdf.Name):
                out[_key(k)] = "/" + _nm(v)
            elif _num(v) is not None:
                out[_key(k)] = _num(v)
        return out
    except _QPDF_ERRORS:
        return None


def _catalog_version(pdf):
    """The catalog's /Version (7.5.2), which can raise the header's version."""
    try:
        version = _nm(pdf.Root.get("/Version")) if pdf is not None else None
    except (*_QPDF_ERRORS, AttributeError, TypeError):
        return None
    return version if version and re.fullmatch(r"\d\.\d", version) else None


def _catalog_entries(pdf):
    """The catalog as {key: its value as written}, to tell what an update did to it."""
    try:
        root = pdf.Root if pdf is not None else None
        return {k: v.unparse() if isinstance(v, pikepdf.Object) else repr(v) for k, v in root.items()} if root else None
    except (*_QPDF_ERRORS, AttributeError, TypeError, ValueError):
        return None


def _validation_only(prev, rev):
    """True for an update that only stores signature validation data (the
    Document Security Store used for long-term validation): it adds objects,
    one of them the /DSS, and modifies nothing but the catalog and the
    document's own metadata (Info, XMP), as real updates of this kind do. In
    the catalog it may add /DSS, /Extensions or /Version and must leave every
    other entry, the page tree included, as it was. Any looser test lets a
    token /DSS object excuse a real change."""
    before, after = prev["_catalog"], rev["_catalog"]
    return (
        before is not None and after is not None and not rev["changes_truncated"]
        and any(c["type"] == "DSS" for c in rev["changes"])
        and all(c["change"] == "added" or (c["change"] == "modified" and c["type"] in ("Catalog", "Info", "Metadata/XML"))
                for c in rev["changes"])
        and all(after.get(k) == v for k, v in before.items())
        and set(after) - set(before) <= {"/DSS", "/Extensions", "/Version"}
    )


def _nonstandard_filters(raw, table):
    """Stream filters that ISO 32000 does not define, as {name: count}. Data
    behind such a filter cannot be decoded, so it cannot be inspected."""
    found, seen = Counter(), set()
    for m in _FILTER.finditer(raw.data):
        names = [m.group(1)] if m.group(1) is not None else _FILTER_NAME.findall(m.group(2))
        if all(n in _STANDARD_FILTERS for n in map(unescape_name, names)):
            continue
        h, objgen = raw.header_before(m.start())
        if h is None or h in seen or (table is not None and table.get(objgen) != h):
            continue  # not a live object, or already counted
        seen.add(h)
        # Only a stream's own /Filter counts: the key also names the handler in
        # signature and encryption dictionaries (12.8.1, 7.6.1).
        try:
            value = parse_indirect(raw.data, h)[2]
            chain = value.dict.get("Filter") if isinstance(value, Stream) else None
            chain = [n.encode("utf-8", "replace") for n in (chain if isinstance(chain, list) else [chain])
                     if isinstance(n, str)]
        except (PdfError, RecursionError):
            # A dictionary too malformed to parse (readers tolerate some): take
            # the names as written, if a stream follows before the next object.
            nxt = bisect.bisect_right(raw.headers, m.start())
            end = raw.headers[nxt] if nxt < len(raw.headers) else len(raw.data)
            chain = [unescape_name(n) for n in names] if _STREAM_START.search(raw.data, m.end(), end) else []
        found.update(n.decode("latin-1") for n in chain if n not in _STANDARD_FILTERS)
    return dict(sorted(found.items()))


def _hex_id(trailer):
    ids = trailer.get("ID")
    if isinstance(ids, list) and len(ids) == 2 and all(isinstance(x, bytes) for x in ids):
        return [x.hex() for x in ids]
    return None


def _locate(raw, objgen, offset):
    """The header offset a cross-reference entry really refers to, or None."""
    for base in dict.fromkeys((offset, offset + raw.header_offset)):
        at = skip_ws(raw.data, base)
        if raw.header_at.get(at) == objgen:
            return at
    return None


def _revisions(raw, final, final_table, final_bad, locked, password):
    """One record per revision, plus cross-reference entries that point at the
    wrong place and object headers nothing points at."""
    data, view = raw.data, memoryview(raw.data)
    out, mismatches, orphans, reported = [], [], [], set()
    digest, pos = hashlib.sha256(), 0
    prev_pdf, prev_table = None, None
    last = len(raw.revisions) - 1
    for rev in raw.revisions:
        digest.update(view[pos : rev.end])
        pos = rev.end
        pdf, table, bad = (final, final_table, final_bad) if rev.index == last else (None, None, [])
        problems = []
        if rev.index != last and not locked:
            try:
                pdf = _open(data[: rev.end], password)
                table, bad = _table(pdf, raw)
            except _QPDF_ERRORS as exc:
                problems.append("qpdf could not open this revision: %s" % _plain(exc))

        counts, detail, truncated = None, [], False
        if table is not None:
            changes = []
            if rev.index == 0:
                counts = {"added": len(table), "modified": 0, "deleted": 0}
            elif prev_table is not None:
                before, now = {n for n, _ in prev_table}, {n for n, _ in table}
                for objgen in sorted(table):
                    if prev_table.get(objgen) != table[objgen]:
                        changes.append((objgen, "modified" if objgen[0] in before else "added"))
                changes += [(objgen, "deleted") for objgen in sorted(prev_table) if objgen[0] not in now]
                tally = Counter(c for _, c in changes)
                counts = {k: tally.get(k, 0) for k in ("added", "modified", "deleted")}
                truncated = len(changes) > 500
                try:
                    info_ref = pdf.trailer.get("/Info")
                    info_id = info_ref.objgen if isinstance(info_ref, pikepdf.Object) and info_ref.is_indirect else None
                except _QPDF_ERRORS:
                    info_id = None
                for objgen, change in changes[:500]:
                    try:
                        kind = "Info" if objgen == info_id else _label(
                            (prev_pdf if change == "deleted" else pdf).get_object(objgen))
                    except _QPDF_ERRORS:
                        kind = "unparsable"
                    detail.append({"object": objgen[0], "change": change, "type": kind})

            # Entries that point at nothing, each reported for the revision it first appears in.
            mismatches += [(rev.index, num, offset) for num, offset in bad if (num, offset) not in reported]
            reported.update(bad)
            # Headers physically present in this revision that its table does not point at.
            lo, hi = bisect.bisect_left(raw.headers, rev.start), bisect.bisect_left(raw.headers, rev.end)
            loose = [raw.headers[i] for i in range(lo, hi) if table.get(raw.header_ids[i]) != raw.headers[i]]
            if loose:
                known = sorted(v for v in table.values() if isinstance(v, int))
                for h in loose:
                    if raw.inside(h, known):
                        continue  # text that looks like a header inside stream data
                    try:
                        value = parse_indirect(data, h)[2]
                        if isinstance(value, Stream) and value.dict.get("Type") == "XRef":
                            continue  # a cross-reference stream need not list itself
                    except (PdfError, RecursionError):
                        pass
                    orphans.append(raw.header_at[h][0])
            if rev.index != last:
                problems += _qpdf_warnings(pdf)

        out.append({
            "revision": rev.index + 1,
            "offset": rev.start,
            "end": rev.end,
            "size": rev.end - rev.start,
            "sha256": digest.copy().hexdigest(),
            "startxref": rev.startxref,
            "xref_type": rev.kind,
            "xref_readable": rev.error is None,
            "prev": rev.prev if isinstance(rev.prev, int) else None,
            "trailer_keys": sorted(str(k) for k in rev.trailer),
            "id": _hex_id(rev.trailer),
            "info": _info(pdf) if pdf is not None else None,
            "catalog_version": _catalog_version(pdf),
            "_catalog": _catalog_entries(pdf),
            "objects": counts,
            "changes": detail,
            "changes_truncated": truncated,
            "signing": False,
            "sealed_by_signature": False,
            "qpdf_warnings": problems,
        })
        if prev_pdf is not None and prev_pdf is not final:
            prev_pdf.close()
        prev_pdf, prev_table = pdf, table
    if prev_pdf is not None and prev_pdf is not final:
        prev_pdf.close()
    digest.update(view[pos:])
    return out, mismatches, orphans, digest.hexdigest()


def _select(raw, pdf, table):
    """The live objects whose dictionaries mention something worth a look, as
    {(num, gen): Counter of the keys found}. Scanning the raw bytes (and
    decoded object streams) for a few keys is far cheaper than visiting every
    object through the binding."""
    picked = {}
    for at, kind in _hits(raw.data):
        h, objgen = raw.header_before(at)
        if h is None or table.get(objgen) != h:
            continue  # not a live object
        # Stream data is skipped. The pattern is only a cheap first test: text in
        # a string can imitate it, so the object is parsed before a hit is dropped.
        if _STREAM_START.search(raw.data, h, at) and at >= raw.dict_end(h):
            continue
        picked.setdefault(objgen, Counter())[kind] += 1
    streams = {}
    for objgen, key in table.items():
        if isinstance(key, tuple):
            streams.setdefault(key[0], {})[key[1]] = objgen
    for num, members in streams.items():
        try:
            holder = pdf.get_object((num, 0))
            if not isinstance(holder, pikepdf.Stream):
                continue
            # qpdf decodes object streams itself to resolve the objects in them,
            # so the size allowed here is generous.
            body, first = _decoded(holder, pdf.is_encrypted, 64 << 20, 16 << 20), int(holder.get("/First"))
            starts = [int(x) for x in body[:first].split()[1::2]]
        except (*_QPDF_ERRORS, ValueError, TypeError):
            continue
        for at, kind in _hits(body, first):
            objgen = members.get(bisect.bisect_right(starts, at - first) - 1)
            if objgen is not None:
                picked.setdefault(objgen, Counter())[kind] += 1
    return picked


def _signature(raw, d, number, live):
    data = raw.data
    br = d.get("/ByteRange") if not isinstance(d, dict) else d.get("ByteRange")
    values = list(br) if isinstance(br, (pikepdf.Array, list)) else []
    ok = len(values) >= 4 and len(values) % 2 == 0 and all(
        isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in values)
    values = [int(x) for x in values] if ok else None
    rec = {"object": number, "type": None, "filter": None, "subfilter": None,
           "byte_range": values, "byte_range_valid": ok, "live": live}
    if not isinstance(d, dict):
        rec.update(type=_nm(d.get("/Type")), filter=_nm(d.get("/Filter")), subfilter=_nm(d.get("/SubFilter")))
        for key, field in (("/Name", "signer_name"), ("/M", "date"), ("/Reason", "reason"),
                           ("/Location", "location"), ("/ContactInfo", "contact")):
            v = d.get(key)
            if isinstance(v, pikepdf.String):
                rec[field] = str(v)
        rec["date_iso"] = _iso(rec.get("date"))
    if ok:
        end = values[-2] + values[-1]
        rec["signed_length"] = end
        rec["bytes_after_signature"] = max(0, len(data) - end)
        rec["covers_whole_file"] = not data[end:].strip(WS)
        rec["signed_revision"] = next(
            (r.index + 1 for r in raw.revisions
             if abs(r.end - end) <= 2 and not data[min(end, r.end): max(end, r.end)].strip(WS)), None)
        # 12.8.1: the digest covers everything except the /Contents value itself.
        rec["byte_range_shape_ok"] = (
            len(values) == 4 and values[0] == 0 and values[1] < values[2] <= len(data)
            and data[values[1]: values[1] + 1] == b"<" and data[values[2] - 1: values[2]] == b">")
    return rec


def _image(number, n):
    cs, flt = n.get("/ColorSpace"), n.get("/Filter")
    cs = cs[0] if isinstance(cs, pikepdf.Array) and len(cs) else cs
    return {"object": number, "width": _num(n.get("/Width")), "height": _num(n.get("/Height")),
            "bits_per_component": _num(n.get("/BitsPerComponent")), "color_space": _nm(cs),
            "filter": [_nm(f) for f in (flt if isinstance(flt, pikepdf.Array) else [flt]) if f is not None],
            "bytes": _num(n.get("/Length")), "mask": n.get("/ImageMask") is True}


def _inventory(raw, pdf, table, picked):
    """Fonts, images, signatures and action counts from the selected objects.

    Objects holding fonts, signatures or escaped names are always opened and
    walked. The rest (links, images, attachments) are opened too unless there
    are more than _EXACT_LIMIT of them; then they are counted from the byte
    hits alone and the result is marked as estimated."""
    fonts, images, sigs, counts = {}, [], {}, Counter()
    exact = sum(1 for kinds in picked.values() if not kinds.keys() & _DEEP) <= _EXACT_LIMIT

    def inspect(objgen, n):
        kind, sub, action = _nm(n.get("/Type")), _nm(n.get("/Subtype")), _nm(n.get("/S"))
        if kind == "Font" and sub not in ("CIDFontType0", "CIDFontType2"):
            desc = n.get("/FontDescriptor")
            if sub == "Type0":
                kids = n.get("/DescendantFonts")
                kid = kids[0] if isinstance(kids, pikepdf.Array) and len(kids) else None
                desc = kid.get("/FontDescriptor") if isinstance(kid, pikepdf.Dictionary) else None
            name = _nm(n.get("/BaseFont"))
            embedded = sub == "Type3" or (isinstance(desc, pikepdf.Dictionary) and any(
                k in desc for k in ("/FontFile", "/FontFile2", "/FontFile3")))
            fonts[(name, sub, embedded)] = {
                "name": name, "subtype": sub, "embedded": embedded,
                "subset": bool(name and re.match(r"[A-Z]{6}\+", name))}
        if sub == "Image" and isinstance(n, pikepdf.Stream):
            counts["images"] += 1
            if len(images) < 200:
                images.append(_image(objgen[0], n))
        if "/ByteRange" in n and "/Contents" in n:
            rec = _signature(raw, n, objgen[0], True)
            sigs.setdefault(tuple(rec["byte_range"] or ("invalid", objgen[0])), rec)
        if action == "JavaScript" or "/JS" in n:
            counts["javascript"] += 1
        elif action == "Launch":
            counts["launch_actions"] += 1
        elif action == "URI":
            counts["uri_actions"] += 1
        elif action in ("SubmitForm", "ImportData", "GoToR", "GoToE"):
            counts["remote_actions"] += 1
        if kind == "EmbeddedFile":
            counts["embedded_files"] += 1

    for objgen in sorted(picked):
        kinds = picked[objgen]
        try:
            if exact or kinds.keys() & _DEEP:
                for n in list(_walk(pdf.get_object(objgen))):
                    inspect(objgen, n)
                continue
            counts["javascript"] += max(kinds[b"JavaScript"], kinds[b"JS"])
            counts["launch_actions"] += kinds[b"Launch"]
            counts["uri_actions"] += kinds[b"URI"]
            counts["remote_actions"] += sum(kinds[k] for k in _REMOTE)
            counts["embedded_files"] += kinds[b"EmbeddedFile"]
            if kinds[b"Image"]:
                counts["images"] += 1
                if len(images) < 200:
                    n = pdf.get_object(objgen)
                    if isinstance(n, pikepdf.Stream):
                        images.append(_image(objgen[0], n))
        except _QPDF_ERRORS:
            continue
    # Signature dictionaries still in the file but no longer part of the document.
    for m in _byte_ranges(raw.data):
        key = tuple(int(x) for x in m.groups())
        h, objgen = raw.header_before(m.start())
        if key in sigs or h is None or table.get(objgen) == h or m.start() >= raw.end_of(h):
            continue
        try:
            value = parse_indirect(raw.data, h)[2]
        except (PdfError, RecursionError):
            continue
        if isinstance(value, dict):
            sigs[key] = _signature(raw, {"ByteRange": list(key)}, objgen[0], False)
    fonts = sorted(fonts.values(), key=lambda f: (f["name"] or "", f["subtype"] or ""))
    return fonts, images, sorted(sigs.values(), key=lambda r: r.get("signed_length") or 0), counts, exact


_DIGIT_BEFORE = re.compile(rb"(?<![\d.])(\d)[\x00\t\n\x0c\r ]+\Z")
_NAME_BEFORE = re.compile(rb"/([^\x00\t\n\x0c\r ()<>\[\]{}/%]+)[\x00\t\n\x0c\r ]+\Z")


def _operator(body, op, start=0, end=None):
    """Offsets where the operator `op` stands as a token of its own. Uses
    bytes.find: a regular expression over megabytes of drawing data is slow."""
    end = len(body) if end is None else end
    at = body.find(op, start, end)
    while at >= 0:
        after = at + len(op)
        # An operator is delimited by white space or a delimiter: "(text)Tj" has no space.
        if (at == 0 or body[at - 1] in _NOT_REGULAR) and (after >= len(body) or body[after] in _NOT_REGULAR):
            yield at
        at = body.find(op, at + 1, end)


def _painted(body):
    """Names of the XObjects painted with `/Name Do` (8.8)."""
    names = set()
    for at in _operator(body, b"Do"):
        m = _NAME_BEFORE.search(body, max(0, at - 130), at)
        if m:
            names.add(m.group(1))
    return names


def _has_inline_image(body):
    """True for a BI ... ID inline image (8.9.7)."""
    return any(next(_operator(body, b"ID", at, at + 4000), None) is not None for at in _operator(body, b"BI"))


def _decoded(stream, encrypted, limit=_SNIFF, raw_cap=64 << 10):
    """Up to `limit` decoded bytes of a stream, or None when they cannot be had
    safely. A stream that is only deflated is inflated here with a hard output
    limit. Anything else goes through qpdf, which decodes the whole stream
    before returning, so that path is taken only for small streams with at
    most one expanding filter: a decompression bomb cannot exhaust memory."""
    try:
        flt, parms = stream.get("/Filter"), stream.get("/DecodeParms")
        chain = list(flt) if isinstance(flt, pikepdf.Array) else [] if flt is None else [flt]
        parms = list(parms) if isinstance(parms, pikepdf.Array) else [parms]
        predicted = any(isinstance(p, pikepdf.Dictionary) and p.get("/Predictor") not in (None, 1) for p in parms)
        raw = stream.read_raw_bytes()
        if not encrypted and not chain:
            return raw[:limit]
        if not encrypted and [_nm(f) for f in chain] == ["FlateDecode"] and not predicted:
            return zlib.decompressobj().decompress(raw, limit)
        expanding = sum(_nm(f) in ("FlateDecode", "LZWDecode", "RunLengthDecode") for f in chain)
        if len(raw) > raw_cap or expanding > 1:
            return None
        return stream.read_bytes()[:limit]
    except (*_QPDF_ERRORS, zlib.error):
        return None


def _inherited(obj, key):
    """A page attribute, looked up through /Parent as 7.7.3.4 requires."""
    for _ in range(64):
        if not isinstance(obj, pikepdf.Dictionary):
            return None
        value = obj.get(key)
        if value is not None:
            return value
        obj = obj.get("/Parent")
    return None


def _page(page, number, encrypted, annots):
    obj = page.obj
    fonts, images, chunks, state = set(), set(), [], {"undecoded": False}

    def read(stream):
        body = _decoded(stream, encrypted)
        if body is None:
            state["undecoded"] = True
        else:
            chunks.append(body)
        return body

    def draw(body, res, depth, seen):
        """Follow the XObjects a piece of content paints with the Do operator
        (8.8). Only those are looked at: a resource dictionary may list every
        image of the document on every page."""
        f = res.get("/Font")
        if isinstance(f, pikepdf.Dictionary):
            fonts.update(f.keys())
        xobjects = res.get("/XObject")
        if not isinstance(xobjects, pikepdf.Dictionary):
            return
        if body is None or len(body) >= _SNIFF:  # content unknown or cut short: take all that are listed
            used = list(xobjects.items())[:5000]
        else:
            used = []
            for raw_name in _painted(body):
                name = "/" + unescape_name(raw_name).decode("utf-8", "replace")
                try:
                    used.append((name, xobjects.get(name)))
                except (TypeError, ValueError):
                    continue
        for name, x in used:
            if not isinstance(x, pikepdf.Stream):
                continue
            key = x.objgen if x.is_indirect else name
            if key in seen:
                continue
            seen.add(key)
            sub = _nm(x.get("/Subtype"))
            if sub == "Image":
                images.add(key)
            elif sub == "Form" and depth < 4:
                inner = x.get("/Resources")
                draw(read(x), inner if isinstance(inner, pikepdf.Dictionary) else res, depth + 1, seen)

    contents = obj.get("/Contents")
    for item in contents if isinstance(contents, pikepdf.Array) else [contents]:
        if isinstance(item, pikepdf.Stream):
            read(item)
    own = None if state["undecoded"] else b"\n".join(chunks)
    if own and _has_inline_image(own):
        images.add("inline image")
    res = _inherited(obj, "/Resources")
    if isinstance(res, pikepdf.Dictionary):
        draw(own, res, 0, set())

    body = b"\n".join(chunks)
    found = any(next(_operator(body, op), None) is not None for op in (b"Tj", b"TJ", b"'", b'"'))  # 9.4.3
    has_text = None if state["undecoded"] and not found else found
    text_guess = bool(fonts) if has_text is None else has_text
    if images and text_guess:
        # Text drawn only in render mode 3 (invisible) over an image is what OCR produces.
        modes = {body[m.start(1)] - 48 for at in _operator(body, b"Tr")
                 for m in [_DIGIT_BEFORE.search(body, max(0, at - 8), at)] if m}
        hidden = bool(has_text) and modes == {3}  # 9.3.6: mode 3 is "neither fill nor stroke"
        kind = "image_with_hidden_text" if hidden else "image_and_text"
    elif images:
        kind = "image_only"
    elif text_guess:
        kind = "text"
    else:
        kind = "no_text_no_images"
    box = _inherited(obj, "/MediaBox")
    notes = obj.get("/Annots")
    count = 0
    for a in notes if isinstance(notes, pikepdf.Array) else ():
        if isinstance(a, pikepdf.Dictionary):
            annots[_nm(a.get("/Subtype")) or "unknown"] += 1
            count += 1
    return {
        "page": number,
        "object": obj.objgen[0] or None,
        "media_box": [_num(x) for x in box] if isinstance(box, pikepdf.Array) else None,
        "fonts": len(fonts),
        "images": len(images),
        "text_operators": has_text,
        "annotations": count,
        "kind": kind,
    }


def _pages(pdf, encrypted, warnings):
    pages, annots = [], Counter()
    try:
        for number, page in enumerate(pdf.pages, 1):
            try:
                pages.append(_page(page, number, encrypted, annots))
            except _QPDF_ERRORS as exc:
                pages.append({"page": number, "object": None, "media_box": None, "fonts": 0, "images": 0,
                              "text_operators": None, "annotations": 0, "kind": "unreadable"})
                warnings.append("page %d: %s" % (number, _plain(exc)))
    except _QPDF_ERRORS as exc:
        warnings.append("page tree: %s" % _plain(exc))
    return pages, annots


def _content_profile(pages):
    kinds = {p["kind"] for p in pages}
    if not pages:
        return "no_pages"
    if kinds <= {"image_only"}:
        return "image_only"
    if kinds <= {"image_only", "image_with_hidden_text"}:
        return "image_with_hidden_text"
    if kinds & {"image_only", "image_with_hidden_text"}:
        return "mixed"
    if kinds <= {"no_text_no_images"}:
        return "no_text_no_images"
    return "text"


def _features(root, counts, annots, exact):
    acro, mark = root.get("/AcroForm"), root.get("/MarkInfo")
    names, perms, lang = root.get("/Names"), root.get("/Perms"), root.get("/Lang")
    return {
        "tagged": isinstance(mark, pikepdf.Dictionary) and mark.get("/Marked") is True,
        "structure_tree": "/StructTreeRoot" in root,
        "language": str(lang) if isinstance(lang, pikepdf.String) else None,
        "outlines": "/Outlines" in root,
        "acroform": isinstance(acro, pikepdf.Dictionary),
        "xfa": isinstance(acro, pikepdf.Dictionary) and "/XFA" in acro,
        "open_action": "/OpenAction" in root,
        "additional_actions": "/AA" in root,
        "optional_content": "/OCProperties" in root,
        "names": sorted(_key(k) for k in names.keys()) if isinstance(names, pikepdf.Dictionary) else [],
        "permissions": sorted(_key(k) for k in perms.keys()) if isinstance(perms, pikepdf.Dictionary) else [],
        "javascript": counts["javascript"], "launch_actions": counts["launch_actions"],
        "uri_actions": counts["uri_actions"], "remote_actions": counts["remote_actions"],
        "embedded_files": counts["embedded_files"],
        "counts_estimated": not exact,
        "annotations": dict(sorted(annots.items())),
    }


def _encryption(raw, pdf, locked, password):
    if pdf is not None and pdf.is_encrypted:
        e = pdf.encryption
        # Crypt filters (and with them AES) arrive with V 4; V 1 and 2 are RC4 (7.6.1, 7.6.5).
        methods = ("rc4", "rc4") if e.V < 4 else (e.stream_method.name, e.string_method.name)
        return {"encrypted": True, "decrypted": True, "password": "supplied" if password else "empty",
                "user_password_matched": pdf.user_password_matched,
                "owner_password_matched": pdf.owner_password_matched,
                "V": e.V, "R": e.R, "bits": e.bits, "permissions": e.P,
                "stream_method": methods[0], "string_method": methods[1]}
    enc = raw.revisions[-1].trailer.get("Encrypt")
    if enc is None:
        return {"encrypted": False}
    if isinstance(enc, Ref):  # the encryption dictionary itself is never encrypted (7.6.1)
        copies = [h for h, i in zip(raw.headers, raw.header_ids) if i == tuple(enc)]
        try:
            enc = parse_indirect(raw.data, copies[-1])[2] if copies else None
        except (PdfError, RecursionError):
            enc = None
    enc = enc if isinstance(enc, dict) else {}
    return {"encrypted": True, "decrypted": False, "password": "required" if locked else "not tried",
            "V": enc.get("V"), "R": enc.get("R"), "bits": enc.get("Length"), "permissions": enc.get("P"),
            "filter": str(enc["Filter"]) if "Filter" in enc else None}


def _conformance(xmp, info):
    claims = []

    def add(standard, iso, source):
        for claim in claims:
            if (claim["standard"], claim["iso"]) == (standard, iso):
                claim["source"] += "; " + source
                return
        claims.append({"standard": standard, "iso": iso, "conformance": None, "source": source, "validated": False})

    part = _xmp_value(xmp, NS_PDFA_ID, "part")
    if part:
        conf = _xmp_value(xmp, NS_PDFA_ID, "conformance") or ""
        add("PDF/A-%s%s" % (part, conf.lower()), "ISO 19005-%s" % part,
            "XMP pdfaid:part=%s conformance=%s" % (part, conf or "(none)"))
    part = _xmp_value(xmp, NS_PDFUA_ID, "part")
    if part:
        add("PDF/UA-%s" % part, "ISO 14289-%s" % part, "XMP pdfuaid:part=%s" % part)
    for (_, local), (key, value) in xmp.items():
        v = _first(value)
        if local == "GTS_PDFXVersion" and v:
            add(v, "ISO 15930", "XMP %s" % key)
        elif local == "ISO_PDFEVersion" and v:
            add(v, "ISO 24517", "XMP %s" % key)
        elif local == "GTS_PDFVTVersion" and v:
            add(v, "ISO 16612", "XMP %s" % key)
    if info and info.get("GTS_PDFXVersion") and not any(c["iso"] == "ISO 15930" for c in claims):
        add(info["GTS_PDFXVersion"], "ISO 15930", "Info GTS_PDFXVersion")
    # Older PDF/X files give the level in GTS_PDFXConformance, e.g. version
    # "PDF/X-1:2001" with conformance "PDF/X-1a:2001" (seen in the GWG patches).
    level = (info or {}).get("GTS_PDFXConformance") or next(
        (_first(v) for (_, local), (_, v) in xmp.items() if local == "GTS_PDFXConformance"), None)
    for claim in claims:
        if claim["iso"] == "ISO 15930" and isinstance(level, str):
            claim["conformance"] = level
    return claims


def _provenance(info, xmp, pages, images, history):
    fields = []
    for label, value in [("Info Creator", (info or {}).get("Creator")),
                         ("XMP xmp:CreatorTool", _xmp_value(xmp, NS_XMP, "CreatorTool")),
                         ("Info Producer", (info or {}).get("Producer")),
                         ("XMP pdf:Producer", _xmp_value(xmp, NS_PDF, "Producer"))] + [
                             ("XMP history agent", e["software_agent"]) for e in history]:
        if isinstance(value, str) and value.strip() and (label, value.strip()) not in fields:
            fields.append((label, value.strip()))
    tools, seen = [], set()
    for label, value in fields:
        for rx, tool, cat in _TOOLS:
            if rx.search(value) and (label.split()[-1], tool) not in seen:
                seen.add((label.split()[-1], tool))
                tools.append({"field": label, "value": value, "tool": tool, "category": cat,
                              "role": "authoring" if "Creator" in label else "pdf_writer"})
    primary = [t for t in tools if t["category"] not in ("editor", "esign")] or tools
    origin = primary[0]["category"] if primary else "unknown"
    profile = _content_profile(pages)
    filters = Counter(f for img in images for f in img["filter"])
    evidence = ['%s "%s" matches %s' % (t["field"], t["value"], t["tool"]) for t in tools]
    if profile in ("image_only", "image_with_hidden_text"):
        evidence.append("every page is a full image%s; filters: %s" % (
            " with an invisible text layer (typical of OCR)" if profile == "image_with_hidden_text" else " with no text",
            ", ".join("%s x%d" % kv for kv in sorted(filters.items())) or "none"))
    if filters.get("CCITTFaxDecode") or filters.get("JBIG2Decode"):
        evidence.append("bitonal fax/scan compression (CCITT or JBIG2) is present")
    generation = _GENERATION.get(origin, "unknown")
    if generation in ("unknown", "print_to_pdf", "image_conversion") and profile in ("image_only", "image_with_hidden_text"):
        generation = "scan_or_image_conversion"
    return {
        "creator": (info or {}).get("Creator"),
        "producer": (info or {}).get("Producer"),
        "tools": tools,
        "origin": origin,
        "generation": generation,
        "content_profile": profile,
        "evidence": evidence,
    }


def _tamper(raw, report, extra, now):
    out = []

    def add(ident, severity, title, detail, basis):
        out.append({"id": ident, "severity": severity, "title": title, "detail": detail, "basis": basis})

    revs, sigs = report["revisions"], report["signatures"]
    info, xmp = report["info"] or {}, extra["xmp"]

    if len(revs) > 1:
        plain = [r["revision"] for r in revs[1:] if not r["signing"]]
        add("incremental_updates", "medium" if plain else "info",
            "File was saved incrementally %d time(s) after it was first written" % (len(revs) - 1),
            ("Revisions %s append changes that are not signature-related. " % plain if plain else
             "Every later revision only adds a signature or signature validation data. ")
            + "Each earlier revision can be recovered byte-for-byte.",
            "ISO 32000-1 7.5.6")
    ids = revs[-1]["id"]
    if ids and ids[0] != ids[1]:
        add("id_mismatch", "low", "File identifier shows the file changed after creation",
            "ID[0] %s (set at creation) differs from ID[1] %s (set at last update)." % tuple(ids),
            "ISO 32000-1 14.4")
    first_ids = [r["id"][0] for r in revs if r["id"]]
    if len(set(first_ids)) > 1:
        add("permanent_id_changed", "medium", "Permanent file identifier differs between revisions",
            "ID[0] values across revisions: %s. It must not change on incremental update." % sorted(set(first_ids)),
            "ISO 32000-1 14.4")

    created, modified = parse_date(info.get("CreationDate")), parse_date(info.get("ModDate"))
    if created and modified:
        delta = _later(modified, created)
        if delta is not None and delta < 0:
            # Some writers stamp ModDate a few seconds before CreationDate (seen with Canva).
            add("moddate_before_creation", "low" if delta < -60 else "info", "ModDate is earlier than CreationDate",
                "CreationDate %s, ModDate %s." % (info["CreationDate"], info["ModDate"]), "ISO 32000-1 14.3.3")
        elif delta is not None and delta > 0:
            add("dates_differ", "low" if delta > 5 else "info", "Metadata records a modification after creation",
                "ModDate is %s later than CreationDate." % timedelta(seconds=int(delta)), "ISO 32000-1 14.3.3")
    for name, source, value in (
            [("CreationDate", "Info", info.get("CreationDate")), ("ModDate", "Info", info.get("ModDate"))]
            + [(local, "XMP", _xmp_value(xmp, NS_XMP, local))
               for local in ("CreateDate", "ModifyDate", "MetadataDate")]):
        d = parse_date(value)
        if d and d.replace(tzinfo=d.tzinfo or timezone.utc) > now + timedelta(days=1):
            add("future_date", "low", "%s %s is in the future" % (source, name), "Value: %s." % value, "heuristic")

    basis = "XMP Specification Part 3, Table 20"
    for key, uri, local, severity in (("Producer", NS_PDF, "Producer", "low"), ("Creator", NS_XMP, "CreatorTool", "low"),
                                      ("Title", NS_DC, "title", "info"), ("Subject", NS_DC, "description", "info"),
                                      ("Keywords", NS_PDF, "Keywords", "info"), ("Trapped", NS_PDF, "Trapped", "info")):
        a, b = info.get(key), _xmp_value(xmp, uri, local)
        if isinstance(a, str) and b and _squash(a).lstrip("/").lower() != _squash(b).lower():
            add("info_xmp_mismatch", severity, "Info %s and XMP disagree" % key,
                'Info %s is "%s"; XMP %s is "%s".' % (key, a, xmp[(uri, local)][0], b), basis)
    author, creators = info.get("Author"), xmp.get((NS_DC, "creator"), (0, None))[1]
    creators = [c for c in (creators if isinstance(creators, list) else [creators]) if isinstance(c, str) and c.strip()]
    if isinstance(author, str) and author.strip() and creators:
        # Author is the first dc:creator, or all of them joined by a separator.
        def norm(name):  # separators and their spacing vary between writers
            return re.sub(r"\s*[;,]\s*", ";", _squash(name)).lower()

        if norm(author) not in (norm(creators[0]), ";".join(norm(c) for c in creators)):
            add("info_xmp_mismatch", "info", "Info Author and XMP disagree",
                'Info Author is "%s"; XMP dc:creator is %s.' % (author, creators), basis)
    for key, local in (("CreationDate", "CreateDate"), ("ModDate", "ModifyDate")):
        a, b = parse_date(info.get(key)), parse_date(_xmp_value(xmp, NS_XMP, local))
        if a and b and not _same_time(a, b):
            add("info_xmp_mismatch", "low", "Info %s and XMP xmp:%s disagree" % (key, local),
                "Info: %s; XMP: %s." % (a.isoformat(), b.isoformat()), basis)
    stamp = parse_date(_xmp_value(xmp, NS_XMP, "MetadataDate"))
    gap = _later(modified, stamp) if modified and stamp else None
    if gap is not None and gap > 60:
        # A gap of whole hours with equal minutes and seconds is one moment
        # written with two different UTC offsets, not two saves.
        zone_slip = gap <= 14 * 3600 and gap % 3600 == 0
        add("info_newer_than_xmp", "info" if zone_slip else "medium",
            "Info ModDate is later than the XMP metadata date",
            "Info ModDate %s; xmp:MetadataDate %s. %s" % (
                modified.isoformat(), stamp.isoformat(),
                "The two differ by a whole number of hours, which points to a time-zone slip by the writer."
                if zone_slip else
                "The file was saved again by software that does not maintain XMP, and the Info values are "
                "the ones in force."),
            "ISO 32000-1 14.3.2; XMP Specification Part 3, 2.2.2")
    ticket = report["preflight_ticket"]
    if ticket:
        basis = "GWG Universal Proof of Preflight"
        add("preflight_ticket", "info", "The file carries a preflight ticket",
            'Profile "%s" (%s %s) was run at %s with the result "%s"%s.' % (
                ticket["profile_name"], ticket["profile_creator"], ticket["profile_creator_version"],
                ticket["executed_date"], ticket["results"],
                ": %s" % ticket["results_description"] if ticket["results_description"] else ""), basis)
        if not ticket["signed"]:
            add("preflight_ticket_unsealed", "low", "The preflight ticket is not sealed by its signature",
                'No signature named "%s" is part of the document, so the ticket and the file could have '
                "changed after the preflight check." % PREFLIGHT_SIGNER, basis)
    history = report["xmp_history"]
    if history:
        add("xmp_history", "info", "The XMP metadata records %d event(s) in the file's history" % len(history),
            "; ".join("%s%s%s" % (e["action"] or "?", " by %s" % e["software_agent"] if e["software_agent"] else "",
                                  " at %s" % e["when"] if e["when"] else "") for e in history[-4:]),
            "XMP Specification Part 2, xmpMM:History")

    for a, b in zip(revs, revs[1:]):
        for key in ("Producer", "Creator"):
            x, y = (a["info"] or {}).get(key), (b["info"] or {}).get(key)
            if x != y and (x or y) and a["info"] is not None and b["info"] is not None:
                add("tool_changed_between_revisions", "medium", "%s changed in revision %d" % (key, b["revision"]),
                    'Revision %d: "%s"; revision %d: "%s".' % (a["revision"], x, b["revision"], y), "ISO 32000-1 14.3.3")

    for s in sigs:
        who = "Signature in object %d" % s["object"]
        if s["live"] and (not s["byte_range_valid"] or not s.get("byte_range_shape_ok", True)
                          or s.get("signed_revision") is None):
            add("signature_byte_range_unusual", "medium", who + " has an unusual /ByteRange",
                "ByteRange %s does not have the usual form (start at 0, one gap holding /Contents, "
                "ending at a revision boundary)." % s["byte_range"], "ISO 32000-1 12.8.1")
        if s["live"] and s["byte_range_valid"] and not s["covers_whole_file"]:
            after = [r for r in revs if s.get("signed_revision") and r["revision"] > s["signed_revision"]]
            later = [r["revision"] for r in after if not r["signing"]]
            resigned = [r["revision"] for r in after if r["sealed_by_signature"]]
            if later or s.get("signed_revision") is None:
                severity, what = "high", ("Revisions %s were appended after signing and are not signature-related." % later
                                          if later else "The signed range does not end at a revision boundary.")
            elif resigned:
                # A later signature seals what its revision changed, but no signature is verified here.
                severity, what = "low", ("Revisions %s change the file after this signature and are covered by "
                                         "later signatures, which are not verified here." % resigned)
            else:
                severity, what = "info", "Only signature validation data was added afterwards."
            add("content_after_signature", severity, who + " does not cover the whole file",
                "%d bytes follow the signed range. %s" % (s["bytes_after_signature"], what), "ISO 32000-1 12.8.1")
        if not s["live"]:
            add("signature_removed", "high", who + " is no longer part of the document",
                "A signature dictionary with ByteRange %s is still in the file, but the current "
                "cross-reference data no longer points to it." % s["byte_range"], "heuristic")

    version = report["structure"]["version"]
    if version not in _SPECS:
        add("unknown_pdf_version", "low", "The file declares a PDF version that was never published",
            "It declares PDF %s; the published versions are 1.0 to 1.7 and 2.0." % version,
            "ISO 32000-1 7.5.2; ISO 32000-2")
    for a, b in zip(revs, revs[1:]):
        if a["catalog_version"] and b["catalog_version"] and b["catalog_version"] < a["catalog_version"]:
            add("version_downgraded", "low", "Revision %d lowers the PDF version" % b["revision"],
                "The catalog of revision %d says %s where revision %d said %s. An update may keep or raise "
                "the version, not reduce it." % (b["revision"], b["catalog_version"], a["revision"], a["catalog_version"]),
                "ISO 32000-2 7.5.6 as corrected by the PDF Association errata")
    odd = report["structure"]["nonstandard_filters"]
    if odd:
        add("nonstandard_filter", "low", "Streams use a filter the PDF standard does not define",
            "%s. Data behind such a filter cannot be decoded, so it cannot be inspected."
            % ", ".join("/%s in %d stream(s)" % kv for kv in odd.items()), "ISO 32000-1 7.4, Table 6")
    if raw.trailing_bytes:
        add("trailing_data", "low", "Data follows the final %%EOF marker",
            "%d bytes; begins with %r." % (raw.trailing_bytes, raw.data[raw.revisions[-1].end:][:32]),
            "ISO 32000-1 7.5.5")
    if extra["mismatches"]:
        add("xref_offset_mismatch", "medium", "Cross-reference entries point to the wrong place",
            "%d entries; first: %s." % (len(extra["mismatches"]), ", ".join(
                "object %d at offset %d (revision %d)" % (n, off, r + 1) for r, n, off in extra["mismatches"][:5])),
            "ISO 32000-1 7.5.4")
    broken = [r["revision"] for r in revs if not r["xref_readable"]]
    if broken:
        add("xref_unreadable", "medium", "Cross-reference data could not be read",
            "Revisions %s: the file is damaged, truncated or was edited by hand." % broken, "ISO 32000-1 7.5.4")
    severe = [(r["revision"], [w for w in r["qpdf_warnings"] if _DAMAGE.search(w)]) for r in revs]
    severe = [(n, w) for n, w in severe if w]
    if severe:
        add("structural_damage", "medium", "qpdf had to repair the file's structure",
            "; ".join("revision %d: %s" % (n, " | ".join(w[:3])) for n, w in severe[:3]), "qpdf diagnostics")
    minor = sum(len([w for w in r["qpdf_warnings"] if not _DAMAGE.search(w)]) for r in revs)
    if minor:
        add("syntax_warnings", "info", "The file departs from the PDF syntax in small ways",
            "qpdf reported %d tolerated problem(s), e.g. %s. This describes the software that wrote "
            "the file rather than a later change." % (minor, next(
                w for r in revs for w in r["qpdf_warnings"] if not _DAMAGE.search(w))), "qpdf diagnostics")
    if raw.linearized is not None and not raw.linearized_intact:
        add("linearization_stale", "info", "File was changed after it was linearized",
            "The linearization dictionary records a length of %s bytes; the file is %d bytes."
            % (raw.linearized.get("L"), len(raw.data)), "ISO 32000-1 Annex F, Table F.1")
    if extra["orphans"]:
        add("unreferenced_objects", "low", "Objects exist that no cross-reference section points to",
            "%d objects: %s%s." % (len(extra["orphans"]), extra["orphans"][:20],
                                  " ..." if len(extra["orphans"]) > 20 else ""), "ISO 32000-1 7.5.4")
    deleted = sum((r["objects"] or {}).get("deleted", 0) for r in revs[1:])
    if deleted:
        add("deleted_objects", "low", "Objects were deleted in a later revision",
            "%d objects are marked free but their data is still in the file." % deleted, "ISO 32000-1 7.5.4, 7.5.6")
    edits = [t for t in report["provenance"]["tools"] if t["category"] == "editor"]
    if edits:
        add("editing_tool_named", "info", "Metadata names a PDF editing or manipulation tool",
            "; ".join('%s "%s"' % (t["field"], t["value"]) for t in edits), "heuristic")

    level = max((x["severity"] for x in out), key=_SEVERITY.index, default="none")
    changed = {"incremental_updates", "id_mismatch", "dates_differ", "content_after_signature",
               "tool_changed_between_revisions", "linearization_stale", "deleted_objects", "signature_removed",
               "info_newer_than_xmp"}
    modified_flag = True if any(x["id"] in changed and x["severity"] != "info" or x["id"] == "incremental_updates"
                                for x in out) else None
    return {"level": level, "modified_after_creation": modified_flag, "indicators": out,
            "note": "Indicators are evidence, not proof. A file with no indicators may still have been "
                    "altered and fully re-saved; signature cryptography is not verified here."}


# ---- public API ----------------------------------------------------------------------


def analyze(source, now=None, password=""):
    """Analyze a PDF (path or bytes) and return a JSON-serializable report.

    `password` opens encrypted files (user or owner password); the default
    empty password opens files that only carry owner-password restrictions.
    """
    data, path = _read(source)
    now = now or datetime.now(timezone.utc)
    with ThreadPoolExecutor(2) as pool:  # hashlib releases the GIL on large buffers
        md5 = pool.submit(lambda: hashlib.md5(data).hexdigest())
        sha1 = pool.submit(lambda: hashlib.sha1(data).hexdigest())
        raw, pdf, table, bad, locked, open_error = _load(data, password)
        try:
            return _report(raw, pdf, table, bad, locked, open_error, path, now, password, md5, sha1)
        finally:
            if pdf is not None:
                pdf.close()


def _report(raw, pdf, table, bad, locked, open_error, path, now, password, md5, sha1):
    data = raw.data
    warnings = list(raw.warnings)
    if open_error:
        warnings.append("qpdf could not open the file (%s): only the raw structure is reported" % open_error)
    revisions, mismatches, orphans, sha256 = _revisions(raw, pdf, table, bad, locked, password)

    root = xmp_error = None
    xmp, pages, annots, picked = {}, [], Counter(), set()
    fonts, images, signatures, counts, exact = [], [], [], Counter(), True
    if pdf is not None:
        try:
            root = pdf.Root
            meta = root.get("/Metadata")
            if isinstance(meta, pikepdf.Stream):
                packet = _decoded(meta, pdf.is_encrypted, 8 << 20, 1 << 20)
                if packet is None:
                    raise PdfError("the metadata stream could not be decoded")
                xmp = parse_xmp(packet)
        except PdfError as exc:
            xmp_error = str(exc)
            warnings.append("XMP metadata: %s" % exc)
        except _QPDF_ERRORS as exc:
            warnings.append("document catalog: %s" % _plain(exc))
        pages, annots = _pages(pdf, pdf.is_encrypted, warnings)
        picked = _select(raw, pdf, table)
        fonts, images, signatures, counts, exact = _inventory(raw, pdf, table, picked)
        revisions[-1]["qpdf_warnings"] += _qpdf_warnings(pdf)
    else:  # no object access: signatures can still be located in the raw bytes
        seen = {}
        for m in _byte_ranges(data):
            h, objgen = raw.header_before(m.start())
            key = tuple(int(x) for x in m.groups())
            if h is not None and m.start() < raw.end_of(h):
                seen.setdefault(key, _signature(raw, {"ByteRange": list(key)}, objgen[0], True))
        signatures = sorted(seen.values(), key=lambda r: r.get("signed_length") or 0)

    sealed = {s.get("signed_revision") for s in signatures if s["live"]}
    for prev, r in zip([None, *revisions], revisions):
        r["sealed_by_signature"] = r["revision"] in sealed
        r["signing"] = r["sealed_by_signature"] or (prev is not None and _validation_only(prev, r))
    for r in revisions:
        del r["_catalog"]

    info = revisions[-1]["info"]
    catalog_version = _nm(root.get("/Version")) if isinstance(root, pikepdf.Dictionary) else None
    version = raw.version
    if catalog_version and re.fullmatch(r"\d\.\d", catalog_version) and catalog_version > version:
        version = catalog_version  # 7.5.2: the catalog entry overrides the header when later
    ids = revisions[-1]["id"]
    report = {
        "file": {"path": path, "size": len(data), "md5": md5.result(), "sha1": sha1.result(), "sha256": sha256},
        "engine": {"pdforensic": __version__, "pikepdf": pikepdf.__version__, "qpdf": pikepdf.__libqpdf_version__},
        "structure": {
            "header_version": raw.version,
            "catalog_version": catalog_version,
            "version": version,
            "specification": _SPECS.get(version, "not a published PDF version"),
            "header_offset": raw.header_offset,
            "eof_markers": raw.eof_markers,
            "revision_count": len(revisions),
            "linearized": raw.linearized is not None,
            "linearized_intact": raw.linearized_intact if raw.linearized is not None else None,
            "hybrid_reference": raw.hybrid,
            "objects": len(table) if table is not None else None,
            "object_headers": len(raw.headers),
            "object_streams": len({k[0] for k in table.values() if isinstance(k, tuple)}) if table else 0,
            "trailing_bytes": raw.trailing_bytes,
            "nonstandard_filters": _nonstandard_filters(raw, table),
        },
        "encryption": _encryption(raw, pdf, locked, password),
        "identifiers": {"id": ids, "permanent_equals_changing": (ids[0] == ids[1]) if ids else None},
        "info": info,
        "info_dates": {k: _iso(info.get(k)) for k in ("CreationDate", "ModDate") if info and k in info},
        "xmp": {key: value for key, value in xmp.values()},
        "xmp_history": _history(xmp),
        "preflight_ticket": _preflight(xmp, signatures),
        "xmp_error": xmp_error,
        "conformance_claims": _conformance(xmp, info),
        "revisions": revisions,
        "signatures": signatures,
        "pages": {"count": len(pages), "kinds": dict(Counter(p["kind"] for p in pages)),
                  "details": pages[:50], "details_truncated": len(pages) > 50},
        "fonts": fonts,
        "images": {"count": counts["images"], "details": images},
        "features": _features(root, counts, annots, exact) if isinstance(root, pikepdf.Dictionary) else None,
    }
    report["provenance"] = _provenance(info, xmp, pages, images, report["xmp_history"])
    report["tamper"] = _tamper(raw, report, {"xmp": xmp, "mismatches": mismatches, "orphans": orphans}, now)
    report["warnings"] = warnings
    return report


def recover_revisions(source, out_dir=None, include_current=False, password=""):
    """Write each earlier revision of an incrementally updated PDF to disk.

    A revision is recovered by cutting the file at the end of that revision's
    %%EOF marker (7.5.6: updates are only ever appended), so each output is
    byte-identical to the file as it was saved at that point.
    Returns a list of {"revision", "path", "size", "sha256"}.
    """
    data, path = _read(source)
    raw, pdf = _load(data, password)[:2]
    if pdf is not None:
        pdf.close()
    stem = os.path.splitext(os.path.basename(path))[0] if path else "document"
    out_dir = out_dir or stem + "-revisions"
    revisions = raw.revisions if include_current else raw.revisions[:-1]
    out = []
    for rev in revisions:
        os.makedirs(out_dir, exist_ok=True)
        target = os.path.join(out_dir, "%s-rev%d.pdf" % (stem, rev.index + 1))
        with open(target, "wb") as f:
            f.write(data[: rev.end])
        out.append({"revision": rev.index + 1, "path": target, "size": rev.end,
                    "sha256": hashlib.sha256(data[: rev.end]).hexdigest()})
    return out


def format_report(r):
    """Render a report from analyze() as plain text."""
    s, t, p = r["structure"], r["tamper"], r["provenance"]
    lines = [
        "File        %s (%d bytes)" % (r["file"]["path"] or "<bytes>", r["file"]["size"]),
        "SHA-256     %s" % r["file"]["sha256"],
        "PDF version %s (%s)%s" % (s["version"], s["specification"], ", linearized" if s["linearized"] else ""),
        "Revisions   %d    %%%%EOF markers %d    objects %s    pages %d" % (
            s["revision_count"], s["eof_markers"], "unknown" if s["objects"] is None else s["objects"],
            r["pages"]["count"]),
        "Encrypted   %s" % ("no" if not r["encryption"]["encrypted"] else "yes, %s (password %s)" % (
            "decrypted" if r["encryption"]["decrypted"] else "NOT decrypted", r["encryption"]["password"])),
    ]
    if r["conformance_claims"]:
        lines.append("Claims      " + ", ".join("%s (%s, not validated)" % (c["standard"], c["iso"])
                                                 for c in r["conformance_claims"]))
    lines.append("")
    lines.append("Metadata (Info dictionary)")
    for k, v in (r["info"] or {}).items():
        lines.append("  %-13s %s" % (k, v))
    if not r["info"]:
        lines.append("  (none readable)")
    if r["xmp"]:
        lines.append("Metadata (XMP)")
        for k, v in r["xmp"].items():
            shown = v if isinstance(v, str) else repr(v)
            lines.append("  %-22s %s" % (k, shown if len(shown) <= 160 else shown[:157] + "..."))
    lines.append("")
    lines.append("Provenance   origin=%s  generation=%s  content=%s" % (p["origin"], p["generation"], p["content_profile"]))
    lines.extend("  - " + e for e in p["evidence"])
    lines.append("")
    lines.append("Revisions")
    for rev in r["revisions"]:
        o = rev["objects"] or {"added": 0, "modified": 0, "deleted": 0}
        lines.append("  %d: bytes %d-%d, xref %s, +%d ~%d -%d objects%s" % (
            rev["revision"], rev["offset"], rev["end"], rev["xref_type"], o["added"], o["modified"], o["deleted"],
            " (signing)" if rev["signing"] else ""))
        for c in rev["changes"][:15]:
            lines.append("       %-8s object %d (%s)" % (c["change"], c["object"], c["type"]))
        if len(rev["changes"]) > 15:
            lines.append("       ... %d more" % (len(rev["changes"]) - 15))
    for sig in r["signatures"]:
        lines.append("Signature    object %d, %s, signed revision %s, covers whole file: %s (cryptography not verified)" % (
            sig["object"], sig.get("subfilter"), sig.get("signed_revision"), sig.get("covers_whole_file")))
    lines.append("")
    lines.append("Tamper indicators: level=%s, modified after creation: %s" % (
        t["level"], {True: "yes", None: "no evidence"}[t["modified_after_creation"]]))
    for i in t["indicators"]:
        lines.append("  [%-6s] %s" % (i["severity"], i["title"]))
        lines.append("           %s (%s)" % (i["detail"], i["basis"]))
    if not t["indicators"]:
        lines.append("  none found")
    lines.append("  " + t["note"])
    for w in r["warnings"]:
        lines.append("Warning: " + w)
    return "\n".join(lines)
