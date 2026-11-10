# Vendored pdfresurrect

- Upstream: https://github.com/enferex/pdfresurrect
- Version: v0.24b, commit `35c50ad` ("Bump version to 0.24b beta.")
- Licence: BSD-3-Clause (see `LICENSE`, `AUTHORS` in this directory)

`main.h`, `pdf.h`, `pdfresurrect.1`, `README`, `ChangeLog`, `AUTHORS` and `LICENSE`
are unmodified. `configure`, `configure.ac` and `Makefile.in` were not copied;
the build is `CMakeLists.txt` at the repository root (and `setup.py` for wheels).

## Local patches

Each is marked in the source with a `pdforensic` comment.

| File | Change | Why |
|---|---|---|
| `main.c` | `fopen` modes `"r"`/`"w"`/`"w+"` → `"rb"`/`"wb"`/`"w+b"` | Text mode corrupts PDF bytes on Windows; no effect on POSIX. |
| `main.c` | `<dirent.h>` + `opendir` + `mkdir(dir, S_IRWXU)` → `stat` + `PDFR_MKDIR` (`_mkdir` on Windows) | `<dirent.h>` and POSIX `mkdir` do not exist with MSVC. |
| `main.c`, `pdf.c` | Also accept `\` as a path separator on Windows | Upstream only strips directories at `/`. |
| `pdf.c` `get_header` | Accept a short read instead of requiring 1023 bytes | Upstream exits with "Failed to load PDF header" on any PDF under 1023 bytes. |
| `pdf.c` `get_object_from_here` | Accept a short read instead of requiring 255 bytes | Upstream exits when a cross-reference stream lies within 255 bytes of the end of the file. |

To update: copy the new upstream sources over this directory and re-apply the patches above.

## Known upstream limitations (observed, not patched)

- Cross-reference streams are detected but not decoded (`pdf.c`, "TODO: decode and
  analyze stream"), so there is no per-object summary for such files.
- XMP metadata is not read (`load_creator_from_xml` is a stub).
- Metadata values are cut at 128 bytes (`KV_MAX_VALUE_LENGTH`).
- It exits with "Failed to locate newline character" on the linearized files qpdf
  writes (`tests/fixtures/qpdf_linearized.pdf`); the unpatched v0.24b binary does the same.
- It prints no creator information for some files (for example
  `tests/fixtures/reportlab.pdf`).
- `-w` writes each version as a full copy of the file with an older `startxref`
  appended, not as the original bytes of that version. `pdforensic recover`
  writes the original bytes.
- File offsets are C `long`: files over 2 GB are not supported on Windows. MSVC
  reports the related integer-size conversions in `pdf.c` as warnings (C4244, C4267).
