set( header_files
    helper/fec-helper.h
    model/fec.h
    model/reed_solomon.h
)

set( source_files
    model/fec.cc
    model/reed_solomon.cc
)

build_lib(
  LIBNAME fec
  SOURCE_FILES ${source_files}
  HEADER_FILES ${header_files}
  # TEST_SOURCES ${test_sources}
  GENERATE_EXPORT_HEADER
)