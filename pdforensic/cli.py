"""Command line: pdforensic analyze FILE [--json] | pdforensic recover FILE [-o DIR]."""

import argparse
import json
import sys

from .forensics import PdfError, analyze, format_report, recover_revisions


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pdforensic", description="Forensic analysis of PDF files.")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="report metadata, revisions, tamper indicators and provenance")
    a.add_argument("pdf")
    a.add_argument("--json", action="store_true", help="print the full report as JSON")
    a.add_argument("--password", default="", help="password for an encrypted file")
    r = sub.add_parser("recover", help="write every earlier revision of the file to a directory")
    r.add_argument("pdf")
    r.add_argument("-o", "--out-dir", help="output directory (default: <name>-revisions)")
    r.add_argument("--all", action="store_true", help="also write the current revision")
    r.add_argument("--password", default="", help="password for an encrypted file")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # consoles that cannot show every character
    try:
        if args.command == "analyze":
            report = analyze(args.pdf, password=args.password)
            print(json.dumps(report, indent=2) if args.json else format_report(report))
        else:
            written = recover_revisions(args.pdf, args.out_dir, include_current=args.all, password=args.password)
            for item in written:
                print("revision %d  %d bytes  sha256 %s  %s" % (
                    item["revision"], item["size"], item["sha256"], item["path"]))
            if not written:
                print("The file has a single revision; nothing to recover.")
    except (OSError, PdfError) as exc:
        print("pdforensic: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
