include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

cmake_policy(SET CMP0037 OLD)

add_library(256_Remove\ Repetition SHARED removerepeat.cpp extensionimpl.cpp)
add_library(512_Copy\ to\ Clipboard SHARED copyclipboard.cpp extensionimpl.cpp)
add_library(1024_Bing\ Translate SHARED bingtranslate.cpp extensionimpl.cpp)
add_library(2048_Extra\ Newlines SHARED extranewlines.cpp extensionimpl.cpp)

target_link_libraries(1024_Bing\ Translate winhttp.lib Qt5::Widgets)
