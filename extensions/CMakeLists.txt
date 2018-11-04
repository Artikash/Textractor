include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

cmake_policy(SET CMP0037 OLD)

add_library(Bing\ Translate SHARED bingtranslate/bingtranslate.cpp extensionimpl.cpp)
add_library(Copy\ to\ Clipboard SHARED copyclipboard/copyclipboard.cpp extensionimpl.cpp)
add_library(Extra\ Newlines SHARED extranewlines/extranewlines.cpp extensionimpl.cpp)
add_library(Remove\ Repetition SHARED removerepeat/removerepeat.cpp extensionimpl.cpp)

target_link_libraries(Bing\ Translate winhttp Qt5::Widgets)
