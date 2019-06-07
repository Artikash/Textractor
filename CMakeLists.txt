cmake_minimum_required(VERSION 3.5)

project(Textractor)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_compile_options(
  /std:c++17
  /MP
  /wd4018 # signed/unsigned mismatch
  /DVERSION="${VERSION}"
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

include_directories(include)
link_directories(${LIBDIR})
file(GLOB LIBS ${LIBDIR}/*)
file(COPY ${LIBS} DESTINATION ${CMAKE_FINAL_OUTPUT_DIRECTORY})

add_library(text text.cpp)
target_compile_definitions(text PRIVATE ${TEXT_LANGUAGE})
link_libraries(text)

add_subdirectory(GUI)
add_subdirectory(GUI/host)
add_subdirectory(texthook)
add_subdirectory(extensions)
