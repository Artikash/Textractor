include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

cmake_policy(SET CMP0037 OLD)

add_library(Bing\ Translate SHARED bingtranslate.cpp extensionimpl.cpp)
add_library(Copy\ to\ Clipboard SHARED copyclipboard.cpp extensionimpl.cpp)
add_library(Extra\ Newlines SHARED extranewlines.cpp extensionimpl.cpp)
add_library(Extra\ Window SHARED extrawindow.cpp extensionimpl.cpp)
add_library(Google\ Translate SHARED googletranslate.cpp extensionimpl.cpp)
add_library(Regex\ Filter SHARED regexfilter.cpp extensionimpl.cpp)
add_library(Remove\ Repetition SHARED removerepeat.cpp extensionimpl.cpp)
add_library(Thread\ Linker SHARED threadlinker.cpp extensionimpl.cpp)

add_executable(Extension_Tests extensiontester.cpp)

target_link_libraries(Bing\ Translate winhttp Qt5::Widgets)
target_link_libraries(Extra\ Window Qt5::Widgets)
target_link_libraries(Google\ Translate winhttp Qt5::Widgets)
target_link_libraries(Regex\ Filter Qt5::Widgets)
target_link_libraries(Thread\ Linker Qt5::Widgets)
