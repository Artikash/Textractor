cmake_minimum_required(VERSION 3.5)

set(MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.cmake/Modules")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MODULE_DIR})

project(NextHooker)

add_compile_options(
  /std:c++17
  /MP
)

add_definitions(
  /DUNICODE # config.pri
  /D_UNICODE
)

include_directories(include)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Build)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

add_subdirectory(GUI)
add_subdirectory(vnrhook)
add_subdirectory(extensions)
