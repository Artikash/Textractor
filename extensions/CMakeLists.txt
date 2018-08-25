cmake_policy(SET CMP0037 OLD)

add_library(1_Remove\ Repetition SHARED removerepeat.cpp)
add_library(2_Copy\ to\ Clipboard SHARED copyclipboard.cpp)
add_library(3_Google\ Translate SHARED googletranslate.cpp)
add_library(4_Extra\ Newlines SHARED extranewlines.cpp)

target_link_libraries(3_Google\ Translate winhttp.lib)