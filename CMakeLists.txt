cmake_minimum_required(VERSION 2.8)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

project(NextHooker)

set(CMAKE_INSTALL_PREFIX "" CACHE FILEPATH "installation path")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release")

set(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION ON)

execute_process(COMMAND "cmd" " /C date /T" OUTPUT_VARIABLE FULLDATE)
# set(DATE "07/13/2018")
string(SUBSTRING ${FULLDATE} 4 10 BUILD_DATE)
set(BUILD_DATE ${BUILD_DATE})

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 4)
set(CPACK_SOURCE_GENERATOR "ZIP")
set(CPACK_SOURCE_IGNORE_FILES "/CVS/;/\\\\.svn/;/\\\\.bzr/;/\\\\.hg/;/\\\\.git/;\\\\.swp$;\\\\.#;/#" ".*\\\\.user$" "\\\\.gitignore$" "\\\\.gitmodules$" "\\\\.git$")
include(CPack)

add_compile_options(
  #/Zc:auto # config.pri
  /wd4819 # config.pri
  /MP
  /GS-
  $<$<CONFIG:MinSizeRel>:/MT>
  #$<$<CONFIG:Debug>:/MTd>
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
  texthook
)

add_subdirectory(texthook)
add_subdirectory(vnrhook)
# add_subdirectory(profile)
