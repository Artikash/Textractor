set(vnrhost_src
  host.cc
  textthread.cc
)

add_library(vnrhost ${vnrhost_src})

set_target_properties(vnrhost PROPERTIES LINK_FLAGS /SUBSYSTEM:WINDOWS)

target_compile_options(vnrhost PRIVATE
#  /GR-
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

target_compile_definitions(vnrhost
  PRIVATE
  ITH_HAS_CRT
  _CRT_NON_CONFORMING_SWPRINTFS
)
