macro(msvc_registry_search)
	if(NOT EXISTS Qt5_DIR AND MSVC)
		# look for user-registry pointing to qtcreator
		get_filename_component(QT_BIN [HKEY_CURRENT_USER\\Software\\Classes\\Applications\\QtProject.QtCreator.pro\\shell\\Open\\Command] PATH)

		# get root path so we can search for 5.3, 5.4, 5.5, etc
		string(REPLACE "/Tools" ";" QT_BIN "${QT_BIN}")
		list(GET QT_BIN 0 QT_BIN)
		file(GLOB QT_VERSIONS "${QT_BIN}/5.1*")
		list(SORT QT_VERSIONS)

		# assume the latest version will be last alphabetically
		list(REVERSE QT_VERSIONS)

		list(GET QT_VERSIONS 0 QT_VERSION)

		# fix any double slashes which seem to be common
		string(REPLACE "//" "/"  QT_VERSION "${QT_VERSION}")

		if(MSVC_VERSION GREATER_EQUAL 1920)
			set(QT_MSVC 2019)
		elseif(MSVC_VERSION GREATER_EQUAL 1910)
			set(QT_MSVC 2017)
		elseif(MSVC_VERSION GREATER_EQUAL 1900)
			set(QT_MSVC 2015)
		else()
			message(WARNING "Unsupported MSVC toolchain version")
		endif()

		if(QT_MSVC)
			if(CMAKE_CL_64)
				SET(QT_SUFFIX "_64")
			else()
				set(QT_SUFFIX "")
			endif()

			# MSVC 2015+ is only backwards compatible
			if(EXISTS "${QT_VERSION}/msvc${QT_MSVC}${QT_SUFFIX}")
				set(Qt5_DIR "${QT_VERSION}/msvc${QT_MSVC}${QT_SUFFIX}/lib/cmake/Qt5")
			elseif(QT_MSVC GREATER_EQUAL 2019 AND EXISTS "${QT_VERSION}/msvc2017${QT_SUFFIX}")
				set(Qt5_DIR "${QT_VERSION}/msvc2017${QT_SUFFIX}/lib/cmake/Qt5")
			elseif(QT_MSVC GREATER_EQUAL 2017 AND EXISTS "${QT_VERSION}/msvc2015${QT_SUFFIX}")
				set(Qt5_DIR "${QT_VERSION}/msvc2015${QT_SUFFIX}/lib/cmake/Qt5")
			else()
				message(WARNING "Required QT5 toolchain is not installed")
			endif()
		endif()
	endif()
endmacro()

macro(find_qt5)
	set(CMAKE_INCLUDE_CURRENT_DIR ON)
	#set(CMAKE_AUTOMOC ON)
	set(CMAKE_AUTOUIC ON)
	#add_definitions(-DQT_DEPRECATED_WARNINGS -DQT_DISABLE_DEPRECATED_BEFORE=0x060000)
	find_package(Qt5 COMPONENTS ${ARGN})

	if(Qt5_FOUND)
		if(WIN32 AND TARGET Qt5::qmake AND NOT TARGET Qt5::windeployqt)
			get_target_property(_qt5_qmake_location Qt5::qmake IMPORTED_LOCATION)

			execute_process(
				COMMAND "${_qt5_qmake_location}" -query QT_INSTALL_PREFIX
				RESULT_VARIABLE return_code
				OUTPUT_VARIABLE qt5_install_prefix
				OUTPUT_STRIP_TRAILING_WHITESPACE
			)

			set(imported_location "${qt5_install_prefix}/bin/windeployqt.exe")

			if(EXISTS ${imported_location})
				add_executable(Qt5::windeployqt IMPORTED)

				set_target_properties(Qt5::windeployqt PROPERTIES
					IMPORTED_LOCATION ${imported_location}
				)
			endif()
		endif()
	else()
		message(FATAL_ERROR "Cannot find QT5!")
	endif()
endmacro(find_qt5)
