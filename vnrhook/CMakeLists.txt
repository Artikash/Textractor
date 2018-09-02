include_directories(. util)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
set(vnrhook_src
  main.cc
  pipe.cc
  util/ithsys/ithsys.cc
  hijack/texthook.cc
)
else()
set(vnrhook_src
  main.cc
  pipe.cc
  engine/engine.cc
  engine/match.cc
  engine/pchooks.cc
  hijack/texthook.cc
  util/util.cc
  util/ithsys/ithsys.cc
  util/disasm/disasm.cc
  util/memdbg/memsearch.cc
)
endif()

add_subdirectory(libminhook)

add_library(vnrhook SHARED ${vnrhook_src})

enable_language(ASM_MASM)

set_source_files_properties(
  ${PROJECT_SOURCE_DIR}/winseh/safeseh.asm
  PROPERTIES
  # CMAKE_ASM_MASM_FLAGS /safeseh # CMake bug 14711: http://www.cmake.org/Bug/view.php?id=14711
  COMPILE_FLAGS /safeseh
)

set_target_properties(vnrhook PROPERTIES
  LINK_FLAGS "/SUBSYSTEM:WINDOWS /MANIFEST:NO"
)

target_compile_options(vnrhook PRIVATE
  /EHa
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

set(vnrhook_libs
  ntdll.lib
  Version.lib
  minhook
)

target_link_libraries(vnrhook ${vnrhook_libs})

target_compile_definitions(vnrhook
  PRIVATE
  ITH_HAS_CRT
  ITH_HAS_SEH
  _CRT_NON_CONFORMING_SWPRINTFS
)