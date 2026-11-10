"""Raw, byte-level view of a PDF file. Standard library only.

qpdf (via pikepdf) does the object-level work in forensics.py, but like every
PDF library it presents the current document and hides the file's history.
This module recovers what it hides: where each revision ends, which
cross-reference section closes it, and every object header physically
present in the file. Section numbers refer to ISO 32000-1:2008 (PDF 1.7).
"""

from __future__ import annotations

import binascii
import bisect
import re

WS = b"\x00\t\n\x0c\r "  # 7.2.2 white-space characters
_W = rb"[\x00\t\n\x0c\r ]"
_REG = rb"[^\x00\t\n\x0c\r ()<>\[\]{}/%]"  # 7.2.2 regular characters
_NOT_REGULAR = frozenset(WS + b"()<>[]{}/%")

MAX_DEPTH = 100  # cap on array/dictionary nesting


class PdfError(ValueError):
    """The bytes do not form the PDF construct that was expected."""


class Name(str):
    """A PDF name object (/Type). Compares equal to the plain string."""

    __slots__ = ()


class Ref(tuple):
    """An indirect reference (12 0 R)."""

    __slots__ = ()

    def __new__(cls, num, gen=0):
        return tuple.__new__(cls, (num, gen))


class Stream:
    """A stream object: its dictionary plus the byte span of its raw data."""

    __slots__ = ("dict", "start", "end")

    def __init__(self, dict_, start, end):
        self.dict, self.start, self.end = dict_, start, end


_SKIP_RE = re.compile(rb"(?:" + _W + rb"+|%[^\r\n]*)*")  # white space and comments
_NUM_RE = re.compile(rb"[+-]?(?:\d+\.\d*|\.\d+|\d+)")
_REF_RE = re.compile(rb"(\d+)" + _W + rb"+(\d+)" + _W + rb"+R(?!" + _REG + rb")")
_NAME_RE = re.compile(rb"/(" + _REG + rb"*)")
_KW_RE = re.compile(_REG + rb"+")
_NAME_ESC = re.compile(rb"#([0-9A-Fa-f]{2})")
_OCTAL_RE = re.compile(rb"[0-7]{1,3}")
_STR_ESC = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12, 0x28: 0x28, 0x29: 0x29, 0x5C: 0x5C}
_OBJ_RE = re.compile(
    rb"(?<![0-9])(\d{1,10})" + _W + rb"+(\d{1,5})" + _W + rb"+obj(?!" + _REG + rb")"
)
_OBJ_BACK = re.compile(rb"(\d{1,10})" + _W + rb"+(\d{1,5})" + _W + rb"+obj\Z")
_XREF_KEYWORD = re.compile(rb"(?<![A-Za-z])xref(?=" + _W + rb")")
_TERM_RE = re.compile(rb"startxref" + _W + rb"+(\d{1,20})" + _W + rb"*%%EOF(\r\n|\n|\r)?")


def unescape_name(raw):
    """Resolve the #xx escapes of a name (7.3.5)."""
    return _NAME_ESC.sub(lambda h: bytes([int(h.group(1), 16)]), raw)


def skip_ws(data, pos):
    """Offset of the first byte at or after pos that is not white space or a comment."""
    return _SKIP_RE.match(data, pos).end()


class Parser:
    """Parses PDF objects (7.3) out of a byte buffer."""

    def __init__(self, data, pos=0):
        self.data, self.pos = data, pos

    def skip_ws(self):
        self.pos = skip_ws(self.data, self.pos)

    def parse(self, depth=0):
        if depth > MAX_DEPTH:
            raise PdfError("objects nested deeper than %d levels" % MAX_DEPTH)
        self.skip_ws()
        d, p = self.data, self.pos
        c = d[p : p + 1]
        if not c:
            raise PdfError("unexpected end of data")
        if c == b"/":
            m = _NAME_RE.match(d, p)
            self.pos = m.end()
            return Name(unescape_name(m.group(1)).decode("utf-8", "replace"))
        if c == b"(":
            return self._literal()
        if c == b"<":
            if d[p + 1 : p + 2] == b"<":
                return self._dict(depth)
            end = d.find(b">", p)
            if end < 0:
                raise PdfError("unterminated hexadecimal string at offset %d" % p)
            digits = d[p + 1 : end].translate(None, WS)
            self.pos = end + 1
            try:
                return binascii.unhexlify(digits + b"0" * (len(digits) % 2))
            except binascii.Error:
                raise PdfError("invalid hexadecimal string at offset %d" % p) from None
        if c == b"[":
            self.pos = p + 1
            out = []
            while True:
                self.skip_ws()
                if d[self.pos : self.pos + 1] == b"]":
                    self.pos += 1
                    return out
                out.append(self.parse(depth + 1))
        if c in b"+-.0123456789":
            m = _REF_RE.match(d, p)
            try:
                if m:
                    self.pos = m.end()
                    return Ref(int(m.group(1)), int(m.group(2)))
                m = _NUM_RE.match(d, p)
                if m:
                    self.pos = m.end()
                    return float(m.group()) if b"." in m.group() else int(m.group())
            except ValueError:  # absurdly long digit runs
                pass
            raise PdfError("invalid number at offset %d" % p)
        m = _KW_RE.match(d, p)
        if m and m.group() in (b"true", b"false", b"null"):
            self.pos = m.end()
            return {b"true": True, b"false": False, b"null": None}[m.group()]
        raise PdfError("unexpected token %r at offset %d" % (d[p : p + 12], p))

    def _literal(self):  # 7.3.4.2 literal strings
        d, p, n = self.data, self.pos + 1, len(self.data)
        out, depth = bytearray(), 1
        while p < n:
            c = d[p]
            if c == 0x5C:  # backslash escape
                p += 1
                if p >= n:
                    break
                e = d[p]
                if e in _STR_ESC:
                    out.append(_STR_ESC[e])
                    p += 1
                elif 0x30 <= e <= 0x37:
                    m = _OCTAL_RE.match(d, p)
                    out.append(int(m.group(), 8) & 0xFF)
                    p = m.end()
                elif e == 0x0D:  # line continuation
                    p += 2 if d[p + 1 : p + 2] == b"\n" else 1
                elif e == 0x0A:
                    p += 1
                else:
                    out.append(e)
                    p += 1
            elif c == 0x0D:  # an unescaped end-of-line is read as LF
                out.append(0x0A)
                p += 2 if d[p + 1 : p + 2] == b"\n" else 1
            elif c == 0x28:
                depth += 1
                out.append(c)
                p += 1
            elif c == 0x29:
                depth -= 1
                p += 1
                if depth == 0:
                    self.pos = p
                    return bytes(out)
                out.append(c)
            else:
                out.append(c)
                p += 1
        raise PdfError("unterminated literal string at offset %d" % self.pos)

    def _dict(self, depth):
        d = self.data
        self.pos += 2
        out = {}
        while True:
            self.skip_ws()
            if d.startswith(b">>", self.pos):
                self.pos += 2
                return out
            key = self.parse(depth + 1)
            if not isinstance(key, Name):
                raise PdfError("dictionary key is not a name near offset %d" % self.pos)
            out[key] = self.parse(depth + 1)


def parse_indirect(data, pos):
    """Parse 'N G obj ... endobj' at pos. Returns (num, gen, value, end_offset)."""
    m = _OBJ_RE.match(data, pos)
    if not m:
        raise PdfError("no indirect object at offset %d" % pos)
    p = Parser(data, m.end())
    value = p.parse()
    p.skip_ws()
    if isinstance(value, dict) and data.startswith(b"stream", p.pos):  # 7.3.8
        s = p.pos + 6
        if data.startswith(b"\r\n", s):
            s += 2
        elif data[s : s + 1] in (b"\n", b"\r"):
            s += 1
        e = None
        length = value.get("Length")
        if isinstance(length, int) and not isinstance(length, bool) and 0 <= length <= len(data) - s:
            if data[s + length : s + length + 16].lstrip(WS).startswith(b"endstream"):
                e = s + length
        if e is None:
            # ponytail: an indirect or wrong /Length falls back to searching for
            # "endstream". Resolve /Length through the xref instead if raw stream
            # data that itself contains "endstream" ever causes a wrong cut.
            e = data.find(b"endstream", s)
            if e < 0:
                raise PdfError("stream at offset %d has no endstream" % pos)
            if e - 2 >= s and data[e - 2 : e] == b"\r\n":
                e -= 2
            elif e - 1 >= s and data[e - 1 : e] in (b"\n", b"\r"):
                e -= 1
        value = Stream(value, s, e)
        p.pos = data.find(b"endstream", e) + 9
        p.skip_ws()
    end = p.pos
    if data.startswith(b"endobj", end):
        end += 6
    return int(m.group(1)), int(m.group(2)), value, end


class Revision:
    """The original file body or one incremental update (7.5.6)."""

    __slots__ = ("index", "start", "end", "startxref", "kind", "trailer", "prev", "error")


class RawPdf:
    """Header, object headers, %%EOF trailers and revision boundaries."""

    def __init__(self, data):
        self.data = data
        self.warnings = []
        m = re.search(rb"%PDF-(\d)\.(\d)", data[:1024])
        if not m:
            raise PdfError("not a PDF: no %PDF-M.m header in the first 1024 bytes")
        self.header_offset = m.start()
        self.version = "%s.%s" % (m.group(1).decode(), m.group(2).decode())
        if self.header_offset:
            self.warnings.append("%d bytes precede the %%PDF header" % self.header_offset)

        # Every "N G obj" header in the file. Stream data is not skipped here,
        # so a header can be a false hit inside a stream; callers check a
        # header against the cross-reference data before trusting it.
        self.headers, self.header_ids = [], []
        find, p, n = data.find, data.find(b"obj"), len(data)
        while p >= 0:
            if p and data[p - 1] in WS and (p + 3 == n or data[p + 3] in _NOT_REGULAR):
                h = _OBJ_BACK.search(data, max(0, p - 32), p + 3)
                if h and (h.start() == 0 or not 0x30 <= data[h.start() - 1] <= 0x39):
                    self.headers.append(h.start())
                    self.header_ids.append((int(h.group(1)), int(h.group(2))))
            p = find(b"obj", p + 3)

        # (offset of "startxref", its value, offset after %%EOF, offset after the EOL)
        self.candidates = [
            (t.start(), int(t.group(1)), t.end() - len(t.group(2) or b""), t.end())
            for t in _TERM_RE.finditer(data)
        ]
        self.eof_markers = data.count(b"%%EOF")
        self._ends = {}
        self.header_at = dict(zip(self.headers, self.header_ids))

        # Linearization parameter dictionary: the first object, within the
        # first 1024 bytes (Annex F.3.3).
        self.linearized = None
        if self.headers and self.headers[0] < 1024 + self.header_offset:
            try:
                value = parse_indirect(data, self.headers[0])[2]
                if isinstance(value, dict) and "Linearized" in value:
                    self.linearized = value
            except (PdfError, RecursionError):
                pass

    def _span(self, offset):
        """(where the dictionary of the object at `offset` ends, where the object ends)."""
        if offset not in self._ends:
            try:
                _, _, value, end = parse_indirect(self.data, offset)
                self._ends[offset] = (value.start if isinstance(value, Stream) else end, end)
            except (PdfError, RecursionError):
                self._ends[offset] = (len(self.data), offset)  # unparsable: assume all of it is dictionary
        return self._ends[offset]

    def end_of(self, offset):
        """Offset just past the object that starts at `offset`."""
        return self._span(offset)[1]

    def dict_end(self, offset):
        """Offset where the stream data of the object at `offset` begins (its end, if it is not a stream)."""
        return self._span(offset)[0]

    def header_before(self, pos):
        """(offset, (num, gen)) of the last object header at or before pos."""
        i = bisect.bisect_right(self.headers, pos) - 1
        return (self.headers[i], self.header_ids[i]) if i >= 0 else (None, None)

    def inside(self, pos, objects):
        """True if pos lies inside one of the objects starting at the sorted offsets `objects`."""
        i = bisect.bisect_right(objects, pos) - 1
        return i >= 0 and pos < self.end_of(objects[i])

    def build_revisions(self, objects=()):
        """Split the file into revisions. `objects` holds the sorted offsets of
        objects known to be real; a startxref/%%EOF pair inside one of them
        (an embedded PDF, say) is data and does not end a revision."""
        data = self.data
        terms = [t for t in self.candidates if not self.inside(t[0], objects)]

        # A linearized file is written with two cross-reference sections and
        # two %%EOF markers (7.5.4); both belong to the first revision. /L is
        # the file length at the time of linearization (Table F.1).
        self.linearized_intact = None
        groups = [[t] for t in terms]
        if self.linearized is not None:
            length = self.linearized.get("L")
            self.linearized_intact = length == len(data)
            k = next((i for i, t in enumerate(terms) if length in (t[2], t[3])), None)
            if k is None:
                self.warnings.append(
                    "linearization dictionary /L (%r) does not match any revision boundary; "
                    "the file is not treated as linearized" % (length,)
                )
                self.linearized = None
            else:
                groups = [terms[: k + 1]] + [[t] for t in terms[k + 1 :]]

        self.revisions = []
        self.hybrid = False
        if not groups:
            self.warnings.append("no startxref/%%EOF trailer found; the file is truncated or damaged")
            groups = [[(len(data), None, len(data), len(data))]]
        start = 0
        for index, group in enumerate(groups):
            rev = Revision()
            rev.index, rev.start, rev.end = index, start, group[-1][3]
            rev.startxref = group[-1][1]
            rev.kind, rev.trailer, rev.prev, rev.error = None, {}, None, None
            if rev.startxref is None:
                rev.error = "no cross-reference section"
            else:
                self._read_section(rev)
            if self.revisions and self._closes_hybrid(rev):
                # 7.5.8.4 hybrid-reference file, as Microsoft Office writes it: a
                # table and trailer for PDF 1.4 readers, then an empty table whose
                # trailer points at a cross-reference stream. Two %%EOF markers,
                # one revision.
                last = self.revisions[-1]
                last.end, last.startxref, last.trailer = rev.end, rev.startxref, rev.trailer
                last.kind = "+".join(sorted((set((last.kind or "").split("+")) | set(rev.kind.split("+"))) - {""}))
                self.hybrid = True
                start = rev.end
                continue
            rev.index = len(self.revisions)
            if rev.error:
                self.warnings.append("revision %d: %s" % (rev.index + 1, rev.error))
            else:
                expected = self.revisions[-1].startxref if self.revisions else None
                if rev.prev != expected:
                    self.warnings.append(
                        "revision %d: /Prev is %r but the previous cross-reference section is at %r"
                        % (rev.index + 1, rev.prev, expected)
                    )
            self.revisions.append(rev)
            start = rev.end

        tail = data[self.revisions[-1].end :]
        self.trailing_bytes = len(tail) if tail.strip(WS) else 0
        return self.revisions

    def _closes_hybrid(self, rev):
        """True if this section adds no objects and only attaches a
        cross-reference stream that already lies in the earlier bytes."""
        stream_at = rev.trailer.get("XRefStm")
        return (
            rev.error is None
            and isinstance(stream_at, int) and not isinstance(stream_at, bool) and stream_at < rev.start
            and bisect.bisect_left(self.headers, rev.start) == bisect.bisect_left(self.headers, rev.end)
        )

    def _section_at(self, offset):
        """(kind, trailer dictionary) of the cross-reference section at offset."""
        d = self.data
        # A table a little before or after the stated offset is still found,
        # as readers do, and the discrepancy is reported.
        # (Offset 0 is the placeholder a linearized file's first trailer carries, not a near miss.)
        near = sorted((m.start() for m in _XREF_KEYWORD.finditer(d, max(0, offset - 1024), offset + 1024)),
                      key=lambda at: abs(at - offset)) if offset else []
        for base in dict.fromkeys((offset, offset + self.header_offset, *near[:1])):
            if base >= len(d):
                continue
            p = Parser(d, base)
            p.skip_ws()
            if d.startswith(b"xref", p.pos):  # 7.5.4 table followed by 7.5.5 trailer
                t = d.find(b"trailer", p.pos)
                if t < 0:
                    raise PdfError("cross-reference table at offset %d has no trailer" % offset)
                trailer = Parser(d, t + 7).parse()
                if not isinstance(trailer, dict):
                    raise PdfError("trailer at offset %d is not a dictionary" % t)
                if p.pos - offset not in (0, self.header_offset) and d[min(offset, p.pos) : max(offset, p.pos)].strip(WS):
                    self.warnings.append("startxref %d is off by %d bytes: the cross-reference table is at %d"
                                         % (offset, p.pos - offset, p.pos))
                return "table", trailer
            if _OBJ_RE.match(d, p.pos):  # 7.5.8 cross-reference stream
                value = parse_indirect(d, p.pos)[2]
                if isinstance(value, Stream) and value.dict.get("Type") == "XRef":
                    return "stream", value.dict
        raise PdfError("startxref offset %d does not point to a cross-reference section" % offset)

    def _read_section(self, rev):
        kinds, seen, nxt = [], set(), rev.startxref
        try:
            while isinstance(nxt, int) and not isinstance(nxt, bool) and nxt not in seen:
                seen.add(nxt)
                kind, trailer = self._section_at(nxt)
                if not kinds:
                    rev.trailer = trailer
                kinds.append(kind)
                if kind == "table" and isinstance(trailer.get("XRefStm"), int):
                    kinds.append("hybrid-stream")  # 7.5.8.4 hybrid-reference file
                nxt = trailer.get("Prev")
                # Sections chained inside this revision (a linearized file's two) belong to it.
                if not (isinstance(nxt, int) and rev.start <= nxt < rev.end):
                    rev.prev = nxt
                    break
        except (PdfError, RecursionError) as exc:
            rev.error = str(exc)
        rev.kind = "+".join(sorted(set(kinds))) if kinds else None
