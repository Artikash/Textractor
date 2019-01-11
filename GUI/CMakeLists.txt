include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)
set(AUTOMOC OFF)

set(RESOURCE_FILES Textractor.rc Textractor.ico)
add_compile_options(/GL)
# Populate a CMake variable with the sources
set(gui_SRCS
	main.cpp
	mainwindow.cpp
	misc.cpp
	exception.cpp
    extenwindow.cpp
	host/host.cpp
	host/textthread.cpp
	host/util.cpp
	${RESOURCE_FILES}
)
add_executable(${PROJECT_NAME} WIN32 ${gui_SRCS})
target_link_libraries(${PROJECT_NAME} Qt5::Widgets winhttp)

install_qt5_libs(${PROJECT_NAME})
