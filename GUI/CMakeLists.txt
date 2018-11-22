include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

set(RESOURCE_FILES Textractor.rc Textractor.ico)
add_compile_options(/GL)
# Populate a CMake variable with the sources
set(gui_SRCS
	main.cpp
	mainwindow.cpp
	misc.cpp
    extenwindow.cpp
	setdialog.cpp
	tests.cpp
	host/host.cc
	host/textthread.cc
	host/util.cpp
	${RESOURCE_FILES}
)
add_executable(${PROJECT_NAME} WIN32 ${gui_SRCS})
target_link_libraries(${PROJECT_NAME} Qt5::Widgets)

install_qt5_libs(${PROJECT_NAME})
