include_directories(. util)

if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
set(texthook_src
  main.cc
  texthook.cc
  engine/match64.cc
  engine/native/pchooks.cc
  util/ithsys/ithsys.cc
  util/util.cc
)
else()
set(texthook_src
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

add_library(texthook SHARED ${texthook_src})

set_target_properties(texthook PROPERTIES
  LINK_FLAGS "/SUBSYSTEM:WINDOWS /MANIFEST:NO"
)

set(texthook_libs
  Version.lib
  minhook
)

target_link_libraries(texthook ${texthook_libs})

target_compile_definitions(texthook
  PRIVATE
  _CRT_NON_CONFORMING_SWPRINTFS
  _SCL_SECURE_NO_WARNINGS # config.pri
  _CRT_SECURE_NO_WARNINGS
)
