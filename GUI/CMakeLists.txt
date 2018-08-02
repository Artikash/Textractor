include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

set(RESOURCE_FILES NextHooker.rc NextHooker.ico)
# Populate a CMake variable with the sources
set(gui_SRCS
	main.cpp
	mainwindow.cpp
	hostsignaller.cpp
	misc.cpp
    extensions.cpp
	${RESOURCE_FILES}
)
add_executable(${PROJECT_NAME} WIN32 ${gui_SRCS})
target_link_libraries(${PROJECT_NAME} Qt5::Widgets vnrhost)

install_qt5_libs(${PROJECT_NAME})
