"""The package version. The single source is the VERSION file at the top of
the repository; the build copies it into the package metadata read here."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("pdforensic-authentic-check")
except PackageNotFoundError:  # running from a source checkout that was never installed
    _file = Path(__file__).resolve().parent.parent / "VERSION"
    __version__ = _file.read_text(encoding="utf-8").strip() if _file.is_file() else "0+unknown"
