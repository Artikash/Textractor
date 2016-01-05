set(profile_src
  Profile.h
  Profile.cpp
  pugiconfig.hpp
  pugixml.cpp
  pugixml.hpp
  misc.h
  misc.cpp
)

add_library(profile STATIC ${profile_src})

target_compile_options(profile PRIVATE
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

#target_link_libraries(profile comctl32.lib)

#target_compile_definitions(profile
#  PRIVATE
#  _CRT_NON_CONFORMING_SWPRINTFS
#)
