# sys.pro
# CONFIG += noqt noeh staticlib

# CONFIG(noeh) {
#   message(CONFIG noeh)
#   QMAKE_CXXFLAGS          += /GR-
#   QMAKE_CXXFLAGS_RTTI_ON  -= /GR
#   QMAKE_CXXFLAGS_STL_ON        -= /EHsc
#   QMAKE_CXXFLAGS_EXCEPTIONS_ON -= /EHsc
#   CONFIG(dll) {
#     QMAKE_LFLAGS +=  /ENTRY:"DllMain"
#   }
# }

set(vnrsys_src
  sys.h
  sys.cc
)

add_library(vnrsys STATIC ${vnrsys_src})

target_compile_options(vnrsys PRIVATE
  # http://msdn.microsoft.com/library/we6hfdy0.aspx
  /GR- # disable RTTI
  # http://msdn.microsoft.com/library/1deeycx5.aspx
  # /EHs-c- # disable exception handling # CMake bug 15243: http://www.cmake.org/Bug/view.php?id=15243
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

STRING(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})

target_link_libraries(vnrsys comctl32.lib)

target_compile_definitions(vnrsys
  PRIVATE
)
