# hook.pro
# CONFIG += eh eha
# include(../dllconfig.pri)

# hookxp.pro
# CONFIG += noeh
# include(../dllconfig.pri)

# dllconfig.pri
# include(../../../config.pri)
# win32 {
#   CONFIG(eh): DEFINES += ITH_HAS_SEH
#   CONFIG(noeh): DEFINES -= ITH_HAS_SEH
# }

# config.pri
#   CONFIG(eha) {
#     message(CONFIG eha)
#     QMAKE_CXXFLAGS_STL_ON        -= /EHsc
#     QMAKE_CXXFLAGS_EXCEPTIONS_ON -= /EHsc
#     QMAKE_CXXFLAGS_STL_ON        += /EHa
#     QMAKE_CXXFLAGS_EXCEPTIONS_ON += /EHa
#   }
#
#  CONFIG(noeh) { # No Exception handler
#    QMAKE_CXXFLAGS          += /GR-
#    QMAKE_CXXFLAGS_RTTI_ON  -= /GR
#    QMAKE_CXXFLAGS_STL_ON        -= /EHsc
#    QMAKE_CXXFLAGS_EXCEPTIONS_ON -= /EHsc
#  }

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(vnrhook_src
  cli.h
  config.h
  hook.h
  main.cc
  engine/engine.cc
  engine/engine.h
  engine/hookdefs.h
  engine/match.cc
  engine/match.h
  engine/pchooks.cc
  engine/pchooks.h
  engine/util.cc
  engine/util.h
  hijack/texthook.cc
  rpc/pipe.cc
  tree/avl.h
  ${PROJECT_SOURCE_DIR}/ccutil/ccmacro.h
  ${PROJECT_SOURCE_DIR}/cpputil/cpplocale.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppmarshal.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppmath.h
  ${PROJECT_SOURCE_DIR}/cpputil/cpppath.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppstring.h
  ${PROJECT_SOURCE_DIR}/cpputil/cpptype.h
  ${PROJECT_SOURCE_DIR}/cpputil/cppunicode.h
  ${PROJECT_SOURCE_DIR}/disasm/disasm.cc
  ${PROJECT_SOURCE_DIR}/memdbg/memdbg.h
  ${PROJECT_SOURCE_DIR}/memdbg/memsearch.cc
  ${PROJECT_SOURCE_DIR}/memdbg/memsearch.h
  ${PROJECT_SOURCE_DIR}/ntinspect/ntinspect.cc
  ${PROJECT_SOURCE_DIR}/ntinspect/ntinspect.h
  ${PROJECT_SOURCE_DIR}/winversion/winversion.cc
  ${PROJECT_SOURCE_DIR}/winversion/winversion.h
  ${common_src}
  ${import_src}
)

source_group("common" FILES ${common_src})
source_group("import" FILES ${import_src})

add_library(vnrhook SHARED ${vnrhook_src})

set(vnrhookxp_src ${vnrhook_src}
  ${PROJECT_SOURCE_DIR}/winseh/winseh.cc
  ${PROJECT_SOURCE_DIR}/winseh/winseh_safe.cc
  ${PROJECT_SOURCE_DIR}/winseh/winseh.h
  ${PROJECT_SOURCE_DIR}/winseh/safeseh.asm
)

enable_language(ASM_MASM)

set_source_files_properties(
  ${PROJECT_SOURCE_DIR}/winseh/safeseh.asm
  PROPERTIES
  # CMAKE_ASM_MASM_FLAGS /safeseh # CMake bug 14711: http://www.cmake.org/Bug/view.php?id=14711
  COMPILE_FLAGS /safeseh
)

add_library(vnrhookxp SHARED ${vnrhookxp_src})

set_target_properties(vnrhook vnrhookxp PROPERTIES
  LINK_FLAGS "/SUBSYSTEM:WINDOWS /MANIFEST:NO"
)

target_compile_options(vnrhook PRIVATE
  /EHa
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

target_compile_options(vnrhookxp PRIVATE
  /GR-
# /EHs-c- # disable exception handling # CMake bug 15243: http://www.cmake.org/Bug/view.php?id=15243
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

if(TARGET vnrhookxp)
  STRING(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
endif(TARGET vnrhookxp)

set(vnrhook_libs
  vnrsys
  ${WDK_HOME}/lib/wxp/i386/ntdll.lib
  Version.lib
)

target_link_libraries(vnrhook ${vnrhook_libs})
target_link_libraries(vnrhookxp ${vnrhook_libs})

target_compile_definitions(vnrhook
  PRIVATE
  -DITH_HAS_SEH
)
target_compile_definitions(vnrhookxp
  PRIVATE
)

install(TARGETS vnrhook vnrhookxp RUNTIME
  DESTINATION .
  CONFIGURATIONS Release
)
