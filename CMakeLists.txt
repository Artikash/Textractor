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

if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
  set(CMAKE_FINAL_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/builds/${CMAKE_BUILD_TYPE}_x64)
  set(LIBDIR x64libs)
else()
  set(CMAKE_FINAL_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/builds/${CMAKE_BUILD_TYPE}_x86)
  set(LIBDIR x86libs)
endif()
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY $<1:${CMAKE_FINAL_OUTPUT_DIRECTORY}>)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY $<1:${CMAKE_FINAL_OUTPUT_DIRECTORY}>)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY $<1:${CMAKE_FINAL_OUTPUT_DIRECTORY}>)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

file(GLOB LIBS ${LIBDIR}/*)
file(COPY ${LIBS} DESTINATION ${CMAKE_FINAL_OUTPUT_DIRECTORY})

include_directories(include)
link_directories(${LIBDIR})

add_library(text text.cpp)
target_compile_definitions(text PRIVATE ${TEXT_LANGUAGE})
link_libraries(text)

add_subdirectory(GUI)
add_subdirectory(GUI/host)
add_subdirectory(texthook)
add_subdirectory(extensions)
