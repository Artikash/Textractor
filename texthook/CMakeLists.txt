project(host)

set(vnrhost_src
  hookman.h
  host.h
  pipe.h
  textthread.h
  winmutex.h
  hookman.cc
  host.cc
  pipe.cc
  textthread.cc
)

add_library(vnrhost SHARED ${vnrhost_src})

set_target_properties(vnrhost PROPERTIES LINK_FLAGS /SUBSYSTEM:WINDOWS)

target_compile_options(vnrhost PRIVATE
#  /GR-
  $<$<CONFIG:Release>:/MT>
  $<$<CONFIG:Debug>:>
)

target_compile_definitions(vnrhost
  PRIVATE
  ITH_HAS_CRT
  _CRT_NON_CONFORMING_SWPRINTFS
)
