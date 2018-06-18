# config.pri
#  DEFINES += _SECURE_SCL=0 _SCL_SECURE_NO_WARNINGS
#  DEFINES += _CRT_SECURE_NO_WARNINGS

cmake_minimum_required(VERSION 2.8)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

project(vnr)

set(WDK_HOME "C:\\WinDDK\\7600.16385.1" CACHE FILEPATH "Windows Driver Kit path")

add_definitions(
  /DUNICODE
  /D_UNICODE
  /D_SECURE_SCL=0
  /D_SCL_SECURE_NO_WARNINGS
  /D_CRT_SECURE_NO_WARNINGS
)

include_directories(
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/texthook
)

add_subdirectory(vnrhook)
add_subdirectory(texthook/host)
add_subdirectory(profile)
