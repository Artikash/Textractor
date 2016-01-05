# # ithsys.pro
# CONFIG += noqt staticlib
# include(../../../config.pri)

# # jichi 7/12/2015: Always enable SEH
# DEFINES += ITH_HAS_SEH

# DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

set(ithsys_src
  ithsys.h
  ithsys.cc
)

add_library(ithsys STATIC ${ithsys_src})

target_compile_options(ithsys PRIVATE
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

target_link_libraries(ithsys comctl32.lib)

target_compile_definitions(ithsys
  PRIVATE
  ITH_HAS_SEH
  _CRT_NON_CONFORMING_SWPRINTFS
)
