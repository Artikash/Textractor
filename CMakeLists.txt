cmake_minimum_required(VERSION 3.5)

set(MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.cmake/Modules")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MODULE_DIR})

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

include_directories(include)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Build)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

add_subdirectory(host)
add_subdirectory(GUI)
add_subdirectory(minhook)
add_subdirectory(vnrhook)
add_subdirectory(extensions)
