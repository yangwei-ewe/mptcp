set( header_files
    helper/fec-helper.h
    model/fec.h
    # model/rscode-gf.hpp
    # model/rscode-poly.hpp
    # model/rscode.h
)

set( source_files
    model/fec.cc
)

build_lib(
  LIBNAME fec
  SOURCE_FILES ${source_files}
  HEADER_FILES ${header_files}
  # TEST_SOURCES ${test_sources}
  GENERATE_EXPORT_HEADER
)