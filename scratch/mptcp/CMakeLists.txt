# Create a custom library
# add_library(
#   scratch-nested-subdir-lib
#   lib/scratch-nested-subdir-library-source.cc
# )

# Link the custom library to the scratch executable
build_exec(
  EXECNAME scratch-mptcp
  SOURCE_FILES mptcp.cpp
  LIBRARIES_TO_LINK ${applications} "${ns3-libs}"
  # use "${ns3-libs}" "${ns3-contrib-libs}" in case you want to link to all
  # enabled modules
  EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/mptcp
)
