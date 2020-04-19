include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

add_executable(Test WIN32 main.cpp resource.rc)

target_precompile_headers(Test REUSE_FROM pch)

target_link_libraries(Test Qt5::Widgets)
