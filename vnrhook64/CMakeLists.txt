project(vnrhook)

include_directories(../vnrhook)

set(vnrhook_src
  ../vnrhook/include/const.h
  ../vnrhook/include/defs.h
  ../vnrhook/include/types.h
  src/main.cc
  src/main.h
  src/pipe.cc
  src/hijack/texthook.cc
  src/hijack/texthook.h
)

add_library(vnrhook SHARED ${vnrhook_src})

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
  Version.lib
)

target_link_libraries(vnrhook ${vnrhook_libs})

target_compile_definitions(vnrhook
  PRIVATE
  ITH_HAS_CRT
  ITH_HAS_SEH
  _CRT_NON_CONFORMING_SWPRINTFS
)