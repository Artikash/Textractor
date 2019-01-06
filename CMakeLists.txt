cmake_minimum_required(VERSION 2.8)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

project(ITHVNR)

set(WDK_HOME "C:\\WinDDK\\7600.16385.1" CACHE FILEPATH "Windows Driver Kit path")
set(CMAKE_INSTALL_PREFIX "" CACHE FILEPATH "installation path")

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
  set(CMAKE_FINAL_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Builds/${CMAKE_BUILD_TYPE}_x64)
else()
  set(CMAKE_FINAL_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Builds/${CMAKE_BUILD_TYPE}_x86)
endif()
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_FINAL_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_FINAL_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_FINAL_OUTPUT_DIRECTORY})

set(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION ON)

execute_process(COMMAND "cmd" " /C date /T" OUTPUT_VARIABLE FULLDATE)
# set(DATE "07/13/2018")
string(SUBSTRING ${FULLDATE} 0 10 BUILD_DATE)
set(BUILD_DATE ${BUILD_DATE})

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_VERSION_MAJOR 3)
set(CPACK_PACKAGE_VERSION_MINOR 5642)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_SOURCE_GENERATOR "ZIP")
set(CPACK_SOURCE_IGNORE_FILES "/CVS/;/\\\\.svn/;/\\\\.bzr/;/\\\\.hg/;/\\\\.git/;\\\\.swp$;\\\\.#;/#" ".*\\\\.user$" "\\\\.gitignore$" "\\\\.gitmodules$" "\\\\.git$")
include(CPack)

add_compile_options(
  #/Zc:auto # config.pri
  /wd4819 # config.pri
  /MP
  /GS-
  $<$<CONFIG:RelWithDebInfo>:/MT>
#  $<$<CONFIG:Debug>:/MTd>
)

add_definitions(
  /D_SECURE_SCL=0 # config.pri
  /D_SCL_SECURE_NO_WARNINGS # config.pri
  /D_CRT_SECURE_NO_WARNINGS # config.pri
  /DUNICODE # config.pri
  /D_UNICODE
  /D_CRT_NON_CONFORMING_SWPRINTFS # common.pri
  /DITH_HAS_CRT
)

include_directories(
  .
  vnr
  vnr/texthook
  ${CMAKE_BINARY_DIR}/gui
)

set(resource_src
  gui/ITHVNR.rc
  gui/icon1.ico
)  

set(ithvnr_src
  gui/command.cpp
  gui/CustomFilter.cpp
  gui/CustomFilter.h
  gui/ITH.h
  gui/language.cpp
  gui/language.h
  gui/main.cpp
  gui/ProcessWindow.cpp
  gui/ProcessWindow.h
  gui/ProfileManager.cpp
  gui/ProfileManager.h
  gui/resource.h
  gui/utility.cpp
  gui/utility.h
  ${CMAKE_BINARY_DIR}/gui/version.h
  gui/version.h.in
  gui/window.cpp
  gui/window.h
  gui/TextBuffer.cpp
  gui/TextBuffer.h
  ${resource_src}
)

source_group("Resource Files" FILES ${resource_src})

add_executable(${PROJECT_NAME} ${ithvnr_src})

add_subdirectory(vnr)
# add_subdirectory(profile)

set_target_properties(${PROJECT_NAME} PROPERTIES
  LINK_FLAGS "/SUBSYSTEM:WINDOWS /MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\""
)

target_compile_definitions(${PROJECT_NAME}
  PRIVATE
  PSAPI_VERSION=1
  DEFAULT_MM
)

target_link_libraries(${PROJECT_NAME}
  profile
  vnrhost
  ithsys
  ntdll.lib
  comctl32.lib
  psapi.lib
)

target_compile_options(${PROJECT_NAME}
  PRIVATE
  /EHsc
)

install(TARGETS ${PROJECT_NAME}
  DESTINATION .
  CONFIGURATIONS Release
)

configure_file(gui/version.h.in gui/version.h)
