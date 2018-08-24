if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
set(minhook_src
  buffer.c
  hook.c
  trampoline.c
  hde/hde64.c
)
else()
set(minhook_src
  buffer.c
  hook.c
  trampoline.c
  hde/hde32.c
)
endif()

add_library(minhook ${minhook_src})