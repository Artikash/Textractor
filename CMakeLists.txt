cmake_minimum_required(VERSION 2.8)

project(NextHooker)

add_compile_options(
  #/Zc:auto # config.pri
  /wd4819 # config.pri
  /MP
  /GS-
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

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

add_subdirectory(texthook)
add_subdirectory(vnrhook)
