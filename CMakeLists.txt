# Builds the vendored pdfresurrect C tool (src/pdfresurrect) on Linux, macOS and Windows.
#   cmake -B build && cmake --build build --config Release
# The binary lands in build/ (build/Release/ with multi-config generators such as Visual Studio).
cmake_minimum_required(VERSION 3.15)
project(pdfresurrect VERSION 0.24 LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(pdfresurrect src/pdfresurrect/main.c src/pdfresurrect/pdf.c)
set_target_properties(pdfresurrect PROPERTIES C_STANDARD 99)

if(MSVC)
  # fopen/strncpy/sprintf are flagged as "unsafe" by MSVC; upstream code relies on them.
  target_compile_definitions(pdfresurrect PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
  target_compile_options(pdfresurrect PRIVATE /W3)
else()
  target_compile_options(pdfresurrect PRIVATE -Wall)
endif()

include(GNUInstallDirs)
install(TARGETS pdfresurrect RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(NOT WIN32)
  install(FILES src/pdfresurrect/pdfresurrect.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif()
