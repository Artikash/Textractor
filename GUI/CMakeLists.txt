include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets)

add_executable(Textractor WIN32 
	main.cpp
	mainwindow.cpp
	extenwindow.cpp
	host/exception.cpp
	host/host.cpp
	host/textthread.cpp
	host/hookcode.cpp
	Textractor.rc
	Textractor.ico
)
target_precompile_headers(Textractor REUSE_FROM pch)
target_link_libraries(${PROJECT_NAME} Qt5::Widgets shell32 winhttp)

if (NOT EXISTS ${CMAKE_FINAL_OUTPUT_DIRECTORY}/Qt5Core.dll)
	if (NOT EXISTS ${CMAKE_FINAL_OUTPUT_DIRECTORY}/Qt5Cored.dll)
		install_qt5_libs(${PROJECT_NAME})
	endif()
endif()
