# texthook.pro
# CONFIG += noqtgui dll #eha # eha will catch all exceptions, but does not work on Windows XP

# DEFINES += ITH_HAS_CRT # Use native CRT

# # TODO: Get rid of dependence on msvc's swprintf
# DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

set(vnrhost_src
  hookman.h
  host.h
  pipe.h
  textthread.h
  hookman.cc
  host.cc
  pipe.cc
  textthread.cc
  ${PROJECT_SOURCE_DIR}/winmutex/winmutex.h
  ${PROJECT_SOURCE_DIR}/extensions/Extensions.cpp
  ${PROJECT_SOURCE_DIR}/extensions/Extensions.h
)

add_library(vnrhost SHARED ${vnrhost_src})

set_target_properties(vnrhost PROPERTIES LINK_FLAGS /SUBSYSTEM:WINDOWS)

target_compile_options(vnrhost PRIVATE
#  /GR-
  $<$<CONFIG:MinSizeRel>:/MT>
  $<$<CONFIG:Debug>:>
)

#STRING(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})

target_link_libraries(vnrhost)

target_compile_definitions(vnrhost
  PRIVATE
  ITH_HAS_CRT
  _CRT_NON_CONFORMING_SWPRINTFS
)

install(TARGETS vnrhost RUNTIME
  DESTINATION .
  CONFIGURATIONS Release
)
