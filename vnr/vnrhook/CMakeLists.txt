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
  src/tree/avl.h
  src/util/growl.h
  src/util/util.cc
  src/util/util.h
  ${PROJECT_SOURCE_DIR}/ccutil/ccmacro.h
  ${PROJECT_SOURCE_DIR}/cpputil/cpplocale.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppmarshal.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppmath.h
  ${PROJECT_SOURCE_DIR}/cpputil/cpppath.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppstring.h
  ${PROJECT_SOURCE_DIR}/cpputil/cpptype.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppunicode.h
  ${PROJECT_SOURCE_DIR}/disasm/disasm.cc
  ${PROJECT_SOURCE_DIR}/hashutil/hashstr.h
  ${PROJECT_SOURCE_DIR}/hashutil/hashutil.h
  ${PROJECT_SOURCE_DIR}/memdbg/memdbg.h
  ${PROJECT_SOURCE_DIR}/memdbg/memsearch.cc
  ${PROJECT_SOURCE_DIR}/memdbg/memsearch.h
  ${PROJECT_SOURCE_DIR}/ntinspect/ntinspect.cc
  ${PROJECT_SOURCE_DIR}/ntinspect/ntinspect.h
  ${PROJECT_SOURCE_DIR}/winkey/winkey.h
  ${PROJECT_SOURCE_DIR}/winversion/winversion.cc
  ${PROJECT_SOURCE_DIR}/winversion/winversion.h
  ${PROJECT_SOURCE_DIR}/winseh/winseh.h
  ${PROJECT_SOURCE_DIR}/winseh/winseh.cc
  ${PROJECT_SOURCE_DIR}/winseh/winseh_safe.cc
  ${PROJECT_SOURCE_DIR}/winseh/safeseh.asm
  ${PROJECT_SOURCE_DIR}/mono/monoobject.h
  ${PROJECT_SOURCE_DIR}/mono/monotype.h
)

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
  ithsys
  ntdll.lib
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
