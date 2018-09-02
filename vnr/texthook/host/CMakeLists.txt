# texthook.pro
# CONFIG += noqtgui dll #eha # eha will catch all exceptions, but does not work on Windows XP

# DEFINES += ITH_HAS_CRT # Use native CRT

# # TODO: Get rid of dependence on msvc's swprintf
# DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

set(vnrhost_src
  avl_p.h
  config.h
  hookman.h
  host.h
  host_p.h
  settings.h
  textthread.h
  textthread_p.h
  hookman.cc
  host.cc
  pipe.cc
  textthread.cc
  ${PROJECT_SOURCE_DIR}/winmaker/winmaker.h
  ${PROJECT_SOURCE_DIR}/winmaker/winmaker.cc
  ${PROJECT_SOURCE_DIR}/winmutex/winmutex.h
#  ${PROJECT_SOURCE_DIR}/wintimer/wintimer.h
#  ${PROJECT_SOURCE_DIR}/wintimer/wintimer.cc
#  ${PROJECT_SOURCE_DIR}/wintimer/wintimerbase.cc
#  ${PROJECT_SOURCE_DIR}/wintimer/wintimerbase.h
  ${PROJECT_SOURCE_DIR}/windbg/windbg.h
  ${PROJECT_SOURCE_DIR}/windbg/windbg_p.h
  ${PROJECT_SOURCE_DIR}/windbg/inject.h
  ${PROJECT_SOURCE_DIR}/windbg/inject.cc
  ${PROJECT_SOURCE_DIR}/windbg/hijack.h
  ${PROJECT_SOURCE_DIR}/windbg/hijack.cc
  ${PROJECT_SOURCE_DIR}/windbg/util.h
#  ${PROJECT_SOURCE_DIR}/windbg/util.cc
  ${PROJECT_SOURCE_DIR}/windbg/unload.h
  ${PROJECT_SOURCE_DIR}/windbg/unload.cc
  ${PROJECT_SOURCE_DIR}/sakurakit/skdebug.h
)

add_library(vnrhost SHARED ${vnrhost_src})

set_target_properties(vnrhost PROPERTIES LINK_FLAGS /SUBSYSTEM:WINDOWS)

target_compile_options(vnrhost PRIVATE
#  /GR-
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

#STRING(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})

target_link_libraries(vnrhost
  ithsys
  profile
  ntdll.lib
)

target_compile_definitions(vnrhost
  PRIVATE
  ITH_HAS_CRT
  _CRT_NON_CONFORMING_SWPRINTFS
)

install(TARGETS vnrhost RUNTIME
  DESTINATION .
  CONFIGURATIONS Release
)
