include_directories(. util)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
set(vnrhook_src
  main.cc
  texthook.cc
  util/ithsys/ithsys.cc
)
else()
set(vnrhook_src
  main.cc
  texthook.cc
  engine/engine.cc
  engine/match.cc
  engine/native/pchooks.cc
  util/util.cc
  util/ithsys/ithsys.cc
  util/disasm/disasm.cc
  util/memdbg/memsearch.cc
)
endif()

add_subdirectory(libminhook)

add_library(vnrhook SHARED ${vnrhook_src})

enable_language(ASM_MASM)

set_target_properties(vnrhook PROPERTIES
  LINK_FLAGS "/SUBSYSTEM:WINDOWS /MANIFEST:NO"
)

target_compile_options(vnrhook PRIVATE
  /wd4819
)

set(vnrhook_libs
  Version.lib
  minhook
)

target_link_libraries(vnrhook ${vnrhook_libs})

target_compile_definitions(vnrhook
  PRIVATE
  _CRT_NON_CONFORMING_SWPRINTFS
  _SCL_SECURE_NO_WARNINGS # config.pri
  _CRT_SECURE_NO_WARNINGS
)