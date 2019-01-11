cmake_minimum_required(VERSION 3.5)

set(MODULE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MODULE_DIR})

project(Textractor)

add_compile_options(
  /std:c++17
  /MP
  /wd4018 # signed/unsigned mismatch
  /DUNICODE # config.pri
  /D_UNICODE
)

include_directories(include)

if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
  set(CMAKE_FINAL_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/builds/${CMAKE_BUILD_TYPE}_x64)
else()
  set(CMAKE_FINAL_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/builds/${CMAKE_BUILD_TYPE}_x86)
endif()
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_FINAL_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_FINAL_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_FINAL_OUTPUT_DIRECTORY})

set(CMAKE_CONFIGURATION_TYPES Debug Release)

file(GLOB MISC_FILES "release/*.dll")
file(COPY ${MISC_FILES} DESTINATION ${CMAKE_FINAL_OUTPUT_DIRECTORY})

add_subdirectory(GUI)
add_subdirectory(vnrhook)
add_subdirectory(extensions)
