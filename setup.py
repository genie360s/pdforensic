"""Build hooks: compile the bundled pdfresurrect C tool into the package.

Project metadata lives in pyproject.toml.
"""

import os

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py

SOURCES = ["src/pdfresurrect/main.c", "src/pdfresurrect/pdf.c"]


class BuildWithPdfresurrect(build_py):
    def run(self):
        super().run()
        from distutils.ccompiler import new_compiler
        from distutils.sysconfig import customize_compiler

        if self.editable_mode:
            target = os.path.join("pdforensic", "_bin")
        else:
            target = os.path.join(self.build_lib, "pdforensic", "_bin")
        try:
            compiler = new_compiler()
            customize_compiler(compiler)
            if compiler.compiler_type == "msvc":
                compiler.define_macro("_CRT_SECURE_NO_WARNINGS")
            build_temp = self.get_finalized_command("build").build_temp
            objects = compiler.compile(SOURCES, output_dir=build_temp)
            compiler.link_executable(objects, "pdfresurrect", output_dir=target)
        except Exception as exc:  # no C compiler: the pure-Python analyzer still works
            if os.environ.get("PDFORENSIC_REQUIRE_BINARY"):
                raise
            self.warn("pdfresurrect was not built (%s); the pdf-meta, pdf-recover and "
                      "pdf-versions commands need it, the analyzer does not." % exc)


class BinaryDistribution(Distribution):
    """Marks the package as platform-specific: it ships a native executable."""

    def has_ext_modules(self):
        return True


class PlatformWheel(bdist_wheel):
    """The executable does not link against Python, so one wheel serves every
    Python 3 on a platform: tag it py3-none-<platform>."""

    def get_tag(self):
        return "py3", "none", super().get_tag()[2]


setup(distclass=BinaryDistribution, cmdclass={"build_py": BuildWithPdfresurrect, "bdist_wheel": PlatformWheel})
