include(QtUtils)
msvc_registry_search()
find_qt5(Core Widgets WinExtras)

add_executable(Textractor WIN32 
	main.cpp
	mainwindow.cpp
	extenwindow.cpp
	attachprocessdialog.cpp
	Textractor.rc
	Textractor.ico
)
target_precompile_headers(Textractor REUSE_FROM pch)
target_link_libraries(Textractor host Qt5::Widgets Qt5::WinExtras shell32 winhttp)

if (NOT EXISTS ${CMAKE_FINAL_OUTPUT_DIRECTORY}/Qt5Core.dll AND NOT EXISTS ${CMAKE_FINAL_OUTPUT_DIRECTORY}/Qt5Cored.dll)
	add_custom_command(TARGET Textractor
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_CURRENT_BINARY_DIR}/windeployqt"
		COMMAND set PATH=%PATH%$<SEMICOLON>${qt5_install_prefix}/bin
		COMMAND Qt5::windeployqt --dir ${CMAKE_FINAL_OUTPUT_DIRECTORY} "${CMAKE_FINAL_OUTPUT_DIRECTORY}/Textractor.exe"
	)
endif()
