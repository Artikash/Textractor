include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

add_executable(${PROJECT_NAME} WIN32 
	main.cpp
	mainwindow.cpp
    extenwindow.cpp
	host/exception.cpp
	host/host.cpp
	host/textthread.cpp
	host/util.cpp
	Textractor.rc
	Textractor.ico
)
target_compile_options(${PROJECT_NAME} PRIVATE $<$<CONFIG:RelWithDebInfo>:/GL>)
target_link_libraries(${PROJECT_NAME} Qt5::Widgets shell32 winhttp $<$<CONFIG:RelWithDebInfo>:-LTCG>)


install_qt5_libs(${PROJECT_NAME}) # can be commented out for consecutive builds
