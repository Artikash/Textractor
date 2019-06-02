include_directories(. util)

if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
set(texthook_src
  main.cc
  texthook.cc
  hookfinder.cc
  engine/match64.cc
  engine/native/pchooks.cc
  util/ithsys/ithsys.cc
  util/util.cc
)
else()
set(texthook_src
  main.cc
  texthook.cc
  hookfinder.cc
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

target_link_libraries(texthook minhook)
