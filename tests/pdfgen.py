"""Deterministic PDF builders for tests. Standard library only.

Files are written byte by byte so each test controls the exact structure
(cross-reference sections, incremental updates, identifiers, signatures).
"""

import re
import zlib


def deflate(data):
    """A zlib stream holding `data` in one stored block. Written by hand so the
    bytes are the same on every platform: zlib.compress output differs between
    zlib and zlib-ng, which some Python builds use."""
    assert len(data) < 65536
    n = len(data)
    return (b"\x78\x01\x01" + n.to_bytes(2, "little") + (n ^ 0xFFFF).to_bytes(2, "little")
            + data + zlib.adler32(data).to_bytes(4, "big"))


CONTENT = b"BT /F1 24 Tf 72 720 Td (Hello forensic world) Tj ET"
FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
ID_A = b"0123456789abcdef0123456789abcdef"
ID_B = b"fedcba9876543210fedcba9876543210"


def info(producer="pdfgen 1.0", creator="pdforensic tests", created="D:20240102030405+00'00'",
         modified="D:20240102030405+00'00'", title="Fixture"):
    return ("<< /Title (%s) /Creator (%s) /Producer (%s) /CreationDate (%s) /ModDate (%s) >>"
            % (title, creator, producer, created, modified)).encode("latin-1")


class Builder:
    def __init__(self, version="1.4"):
        self.buf = bytearray(b"%PDF-" + version.encode() + b"\n%\xe2\xe3\xcf\xd3\n")
        self.entries = {}  # object number -> offset, or None for a freed object
        self.size = 1
        self.prev = None

    @classmethod
    def resume(cls, data):
        """Continue an existing file, ready to append an incremental update."""
        b = cls()
        b.buf = bytearray(data)
        b.size = int(re.findall(rb"/Size (\d+)", data)[-1])
        b.prev = int(re.findall(rb"startxref\s+(\d+)", data)[-1])
        return b

    def obj(self, num, body):
        self.entries[num] = len(self.buf)
        self.buf += b"%d 0 obj\n%s\nendobj\n" % (num, body)
        self.size = max(self.size, num + 1)

    def stream(self, num, dict_body, data):
        self.obj(num, b"<< %s /Length %d >>\nstream\n%s\nendstream" % (dict_body, len(data), data))

    def free(self, num):
        self.entries[num] = None

    def _trailer(self, extra):
        prev = b" /Prev %d" % self.prev if self.prev is not None else b""
        return b"/Size %d %s%s" % (self.size, extra, prev)

    def finish(self, trailer, startxref=None):
        """Close the current section with a cross-reference table (7.5.4)."""
        xref = len(self.buf)
        entries = dict(self.entries)
        if self.prev is None:
            entries[0] = None
        self.buf += b"xref\n"
        nums = sorted(entries)
        i = 0
        while i < len(nums):
            j = i
            while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
                j += 1
            self.buf += b"%d %d\n" % (nums[i], j - i + 1)
            for n in nums[i : j + 1]:
                if entries[n] is None:
                    self.buf += b"0000000000 %05d f \n" % (65535 if n == 0 else 1)
                else:
                    self.buf += b"%010d 00000 n \n" % entries[n]
            i = j + 1
        self.buf += b"trailer\n<< %s >>\nstartxref\n%d\n%%%%EOF\n" % (
            self._trailer(trailer), xref if startxref is None else startxref)
        self.prev, self.entries = xref, {}
        return self

    def finish_stream(self, num, trailer, compressed=None):
        """Close the section with a cross-reference stream (7.5.8), W [1 4 2],
        FlateDecode with the PNG "Up" predictor. `compressed` maps object
        number to (object stream number, index)."""
        xref = len(self.buf)
        self.size = max(self.size, num + 1)
        entries = {n: (1, off, 0) if off is not None else (0, 0, 1) for n, off in self.entries.items()}
        entries[num] = (1, xref, 0)
        if self.prev is None:
            entries[0] = (0, 0, 65535)
        entries.update({n: (2, s, i) for n, (s, i) in (compressed or {}).items()})
        nums = sorted(entries)
        index, rows, prev_row = [], [], bytes(7)
        for n in nums:
            if index and index[-2] + index[-1] == n:
                index[-1] += 1
            else:
                index += [n, 1]
            t, a, b = entries[n]
            row = bytes([t]) + a.to_bytes(4, "big") + b.to_bytes(2, "big")
            rows.append(b"\x02" + bytes((x - y) & 255 for x, y in zip(row, prev_row)))
            prev_row = row
        data = deflate(b"".join(rows))
        self.buf += (b"%d 0 obj\n<< /Type /XRef %s /W [1 4 2] /Index [%s] /Filter /FlateDecode "
                     b"/DecodeParms << /Predictor 12 /Columns 7 >> /Length %d >>\nstream\n%s\nendstream\nendobj\n"
                     % (num, self._trailer(trailer), b" ".join(b"%d" % x for x in index), len(data), data))
        self.buf += b"startxref\n%d\n%%%%EOF\n" % xref
        self.prev, self.entries = xref, {}
        return self

    def bytes(self):
        return bytes(self.buf)


def _base(b, info_body, extra_page=b"", content=CONTENT, resources=b"/Font << /F1 5 0 R >>", catalog=b""):
    b.obj(1, b"<< /Type /Catalog /Pages 2 0 R" + catalog + b" >>")
    b.obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    b.obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
             b"/Resources << " + resources + b" >>" + extra_page + b" >>")
    b.stream(4, b"", content)
    b.obj(5, FONT)
    b.obj(6, info_body)


def trailer(id0=ID_A, id1=ID_A, extra=b""):
    return b"/Root 1 0 R /Info 6 0 R /ID [<%s> <%s>]%s" % (id0, id1, extra)


def simple(**kw):
    """One revision, classic cross-reference table, one page of text."""
    b = Builder()
    _base(b, info(**kw))
    return b.finish(trailer()).bytes()


def updated():
    """simple() plus an incremental update: new Info (different Producer,
    later ModDate), new page content and an added annotation."""
    b = Builder()
    _base(b, info())
    b.finish(trailer())
    b.obj(6, info(producer="Some PDF Editor 9", modified="D:20240305060708+00'00'"))
    b.stream(4, b"", CONTENT.replace(b"Hello", b"Altered"))
    b.obj(7, b"<< /Type /Annot /Subtype /FreeText /Rect [10 10 200 40] /Contents (added later) >>")
    b.obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
             b"/Resources << /Font << /F1 5 0 R >> >> /Annots [7 0 R] >>")
    return b.finish(trailer(id1=ID_B)).bytes()


def deleted():
    """updated() plus a third revision that frees the annotation object."""
    b = Builder.resume(updated())
    b.free(7)
    b.obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
             b"/Resources << /Font << /F1 5 0 R >> >> >>")
    return b.finish(trailer(id1=ID_B)).bytes()


def xref_stream():
    """PDF 1.5: catalog, pages, page, font and Info live in an object stream;
    the cross-reference data is a stream."""
    bodies = [(1, b"<< /Type /Catalog /Pages 2 0 R >>"),
              (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
              (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
                  b"/Resources << /Font << /F1 5 0 R >> >> >>"),
              (5, FONT), (6, info(producer="pdfgen objstm"))]
    head, body = b"", b""
    for num, text in bodies:
        head += b"%d %d " % (num, len(body))
        body += text + b" "
    packed = deflate(head + body)
    b = Builder("1.5")
    b.stream(4, b"", CONTENT)
    b.stream(10, b"/Type /ObjStm /N %d /First %d /Filter /FlateDecode" % (len(bodies), len(head)), packed)
    compressed = {num: (10, i) for i, (num, _) in enumerate(bodies)}
    return b.finish_stream(11, trailer(), compressed).bytes()


def image_only(hidden_text=False):
    """A page that is one full-page image, as a scanner writes it; with
    hidden_text an invisible text layer (render mode 3) is added, as OCR does."""
    b = Builder()
    content = b"q 612 0 0 792 0 0 cm /Im1 Do Q"
    resources = b"/XObject << /Im1 7 0 R >>"
    if hidden_text:
        content += b" BT 3 Tr /F1 10 Tf 72 700 Td (recognised text) Tj ET"
        resources += b" /Font << /F1 5 0 R >>"
    _base(b, info(producer="ScanDevice 2000", creator="ScanDevice"), content=content, resources=resources)
    b.stream(7, b"/Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceGray "
                b"/BitsPerComponent 8 /Filter /DCTDecode", b"\xff\xd8\xff\xd9")
    return b.finish(trailer()).bytes()


XMP = (b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
       b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
       b'<rdf:Description rdf:about="" xmlns:pdf="http://ns.adobe.com/pdf/1.3/" xmlns:xmp="http://ns.adobe.com/xap/1.0/"'
       b' xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"'
       b' pdf:Producer="%(producer)s" xmp:CreatorTool="pdforensic tests" pdfaid:part="1" pdfaid:conformance="B">\n'
       b'<xmp:CreateDate>2024-01-02T03:04:05Z</xmp:CreateDate><xmp:ModifyDate>%(modified)s</xmp:ModifyDate>\n'
       b'<xmp:MetadataDate>%(modified)s</xmp:MetadataDate>%(extra)s\n'
       b'<dc:title><rdf:Alt><rdf:li xml:lang="x-default">Fixture</rdf:li></rdf:Alt></dc:title>\n'
       b'</rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end="w"?>')


def with_xmp(xmp_producer=b"pdfgen 1.0", xmp_modified=b"2024-01-02T03:04:05Z", xmp_extra=b"", info_body=None, **info_kw):
    """simple() plus an XMP metadata stream claiming PDF/A-1b. `xmp_extra` is
    XML placed inside the rdf:Description; `info_body` replaces the Info dictionary."""
    b = Builder()
    _base(b, info_body or info(**info_kw), catalog=b" /Metadata 7 0 R")
    b.stream(7, b"/Type /Metadata /Subtype /XML",
             XMP % {b"producer": xmp_producer, b"modified": xmp_modified, b"extra": xmp_extra})
    return b.finish(trailer()).bytes()


TICKET = (b'<gwg_preflight:profile_name xmlns:gwg_preflight="http://www.gwg.org/ns/gwg_preflight_v1/">'
          b"MagazineAds_1v3</gwg_preflight:profile_name>"
          b'<gwg_preflight:profile_creator xmlns:gwg_preflight="http://www.gwg.org/ns/gwg_preflight_v1/">'
          b"Adobe Acrobat Preflight</gwg_preflight:profile_creator>"
          b'<gwg_preflight:profile_creator_version xmlns:gwg_preflight="http://www.gwg.org/ns/gwg_preflight_v1/">'
          b"8.0</gwg_preflight:profile_creator_version>"
          b'<gwg_preflight:preflight_results xmlns:gwg_preflight="http://www.gwg.org/ns/gwg_preflight_v1/">'
          b"Success</gwg_preflight:preflight_results>"
          b'<gwg_preflight:preflight_executed_date xmlns:gwg_preflight="http://www.gwg.org/ns/gwg_preflight_v1/">'
          b"2024-01-02T03:04:05Z</gwg_preflight:preflight_executed_date>"
          b'<gwg_preflight:profile_fingerprint xmlns:gwg_preflight="http://www.gwg.org/ns/gwg_preflight_v1/">'
          b"ff68-7293-a8ee-524c</gwg_preflight:profile_fingerprint>")


def signed(appended=False, signer=b"Test Signer", xmp_extra=None):
    """A file with a signature dictionary whose /ByteRange covers the whole
    file (the signature value itself is a dummy). With appended=True an
    ordinary incremental update follows the signed revision. `xmp_extra`
    adds an XMP metadata stream holding that XML."""
    b = Builder()
    catalog = b" /AcroForm << /Fields [8 0 R] /SigFlags 3 >>"
    _base(b, info(), catalog=catalog + (b" /Metadata 9 0 R" if xmp_extra is not None else b""))
    placeholder = b"/ByteRange [0000000000 0000000000 0000000000 0000000000]"
    b.obj(7, b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Name (" + signer + b") "
             b"/M (D:20240102030405+00'00') " + placeholder + b" /Contents <" + b"00" * 64 + b"> >>")
    b.obj(8, b"<< /FT /Sig /T (Signature1) /V 7 0 R /Type /Annot /Subtype /Widget /Rect [0 0 0 0] >>")
    if xmp_extra is not None:
        b.stream(9, b"/Type /Metadata /Subtype /XML",
                 XMP % {b"producer": b"pdfgen 1.0", b"modified": b"2024-01-02T03:04:05Z", b"extra": xmp_extra})
    b.finish(trailer())
    start = b.buf.index(b"/Contents <", b.buf.index(b"7 0 obj")) + len(b"/Contents ")
    end = b.buf.index(b">", start) + 1
    byte_range = b"/ByteRange [%010d %010d %010d %010d]" % (0, start, end, len(b.buf) - end)
    at = b.buf.index(placeholder)
    b.buf[at : at + len(placeholder)] = byte_range
    if appended:
        b.obj(6, info(producer="Some PDF Editor 9", modified="D:20240305060708+00'00'"))
        b.stream(4, b"", CONTENT.replace(b"Hello", b"Altered"))
        b.finish(trailer(id1=ID_B))
    return b.bytes()


def hybrid():
    """A hybrid-reference file (7.5.8.4) laid out as Microsoft Office writes it:
    a table and trailer, %%EOF, then an empty table whose trailer adds /Prev
    and /XRefStm, and a second %%EOF. One object lives in an object stream."""
    b = Builder("1.5")
    _base(b, info(producer="pdfgen hybrid"))
    head, body = b"7 0 ", b"<< /Note (stored in an object stream) >> "
    b.stream(10, b"/Type /ObjStm /N 1 /First %d /Filter /FlateDecode" % len(head), deflate(head + body))
    objstm_at = b.entries.pop(10)
    stream_at = len(b.buf)
    rows = b"".join(bytes([t]) + a.to_bytes(4, "big") + c.to_bytes(2, "big")
                    for t, a, c in ((2, 10, 0), (1, objstm_at, 0), (1, stream_at, 0)))
    b.buf += (b"11 0 obj\n<< /Type /XRef /Size 12 /W [1 4 2] /Index [7 1 10 2] /Root 1 0 R /Length %d >>\n"
              b"stream\n%s\nendstream\nendobj\n" % (len(rows), rows))
    b.size = 12
    b.finish(trailer())
    first, second = b.prev, len(b.buf)
    b.buf += b"xref\n0 0\ntrailer\n<< /Size 12 %s /Prev %d /XRefStm %d >>\nstartxref\n%d\n%%%%EOF\n" % (
        trailer(), first, stream_at, second)
    return b.bytes()


def odd_filter():
    """simple() whose page content claims a filter the standard does not define."""
    b = Builder()
    _base(b, info())
    b.stream(4, b"/Filter /XXXDecode", CONTENT)
    return b.finish(trailer()).bytes()


def version_steps(first=b"1.5", second=b"1.6"):
    """Header 1.4, catalog /Version `first`, then an update setting `second`."""
    b = Builder()
    _base(b, info(), catalog=b" /Version /" + first)
    b.finish(trailer())
    b.obj(1, b"<< /Type /Catalog /Pages 2 0 R /Version /" + second + b" >>")
    return b.finish(trailer(id1=ID_B)).bytes()


def unsigned():
    """signed() plus an update that drops the signature field and frees the
    signature dictionary: the signature bytes stay in the file, unreferenced."""
    b = Builder.resume(signed())
    b.obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    b.free(7)
    b.free(8)
    return b.finish(trailer(id1=ID_B)).bytes()


def orphan():
    """simple() with one extra object that no cross-reference entry points to."""
    b = Builder()
    _base(b, info())
    b.obj(9, b"<< /Note (not in the cross-reference table) >>")
    del b.entries[9]
    b.size = 7
    return b.finish(trailer()).bytes()


def embedded_pdf():
    """simple() with a complete PDF stored uncompressed inside a stream, so the
    raw bytes contain a second startxref/%%EOF pair that ends no revision."""
    b = Builder()
    _base(b, info())
    b.stream(7, b"/Type /EmbeddedFile", simple())
    return b.finish(trailer()).bytes()


def javascript(obfuscated=False):
    """simple() with an OpenAction that runs JavaScript; `obfuscated` writes
    the names with #xx escapes (7.3.5), a common way to dodge naive scanners."""
    action = b"<< /S /J#61vaScript /J#53 (app.alert(1)) >>" if obfuscated else b"<< /S /JavaScript /JS (app.alert(1)) >>"
    b = Builder()
    _base(b, info(), catalog=b" /OpenAction 7 0 R")
    b.obj(7, action)
    return b.finish(trailer()).bytes()
