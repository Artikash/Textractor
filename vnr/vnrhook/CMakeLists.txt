# # hook.pro
# # Exception handler to catch all exceptions
# CONFIG += dll noqt eh eha # noeh nosafeseh

# DEFINES += ITH_HAS_CRT ITH_HAS_SEH
# DEFINES += MEMDBG_NO_STL NTINSPECT_NO_STL # disabled as not used

# # jichi 11/13/2011: disable swprinf warning
# DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

# config.pri
#   CONFIG(eha) {
#     message(CONFIG eha)
#     QMAKE_CXXFLAGS_STL_ON        -= /EHsc
#     QMAKE_CXXFLAGS_EXCEPTIONS_ON -= /EHsc
#     QMAKE_CXXFLAGS_STL_ON        += /EHa
#     QMAKE_CXXFLAGS_EXCEPTIONS_ON += /EHa
#   }

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(vnrhook_src
  include/const.h
  include/defs.h
  include/types.h
  src/except.h
  src/main.cc
  src/main.h
  src/pipe.cc
  src/engine/engine.cc
  src/engine/engine.h
  src/engine/hookdefs.h
  src/engine/match.cc
  src/engine/match.h
  src/engine/pchooks.cc
  src/engine/pchooks.h
  src/engine/mono/funcinfo.h
  src/engine/mono/types.h
  src/engine/ppsspp/funcinfo.h
  src/hijack/texthook.cc
  src/hijack/texthook.h
  src/util/growl.h
  src/util/util.cc
  src/util/util.h
  src/util/ithsys/ithsys.cc
  src/util/disasm/disasm.cc
  src/util/memdbg/memdbg.h
  src/util/memdbg/memsearch.cc
  src/util/memdbg/memsearch.h
  src/util/mono/monoobject.h
  src/util/mono/monotype.h
)

include_directories(src/util)

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
    $<$<CONFIG:MinSizeRel>:/MT>
  $<$<CONFIG:Debug>:>
)

set(vnrhook_libs
  "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.17134.0\\um\\x86\\ntdll.lib"
  Version.lib
)

target_link_libraries(vnrhook ${vnrhook_libs})

target_compile_definitions(vnrhook
  PRIVATE
  ITH_HAS_CRT
  ITH_HAS_SEH
  _CRT_NON_CONFORMING_SWPRINTFS
)

install(TARGETS vnrhook RUNTIME
  DESTINATION .
  CONFIGURATIONS Release
)
