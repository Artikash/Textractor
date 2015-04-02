cmake_minimum_required(VERSION 2.8)

set(CMAKE_CONFIGURATION_TYPES Debug Release)

project(vnr)

set(WDK_HOME "C:\\WinDDK\\7600.16385.1" CACHE FILEPATH "path to the Windows DDK directory")

add_definitions(
  -DUNICODE
  -D_UNICODE
)

include_directories(${PROJECT_SOURCE_DIR})

set(common_src
  ${PROJECT_SOURCE_DIR}/ith/common/const.h
  ${PROJECT_SOURCE_DIR}/ith/common/defs.h
  ${PROJECT_SOURCE_DIR}/ith/common/except.h
  ${PROJECT_SOURCE_DIR}/ith/common/growl.h
  ${PROJECT_SOURCE_DIR}/ith/common/memory.h
  ${PROJECT_SOURCE_DIR}/ith/common/types.h
)
  
set(import_src
  ${PROJECT_SOURCE_DIR}/ith/import/mono/funcinfo.h
  ${PROJECT_SOURCE_DIR}/ith/import/mono/types.h
  ${PROJECT_SOURCE_DIR}/ith/import/ppsspp/funcinfo.h
)

add_subdirectory(ith/hook)
add_subdirectory(ith/host)
add_subdirectory(ith/sys)
