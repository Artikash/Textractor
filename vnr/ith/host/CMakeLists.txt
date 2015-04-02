# host.pro
# #CONFIG += eha # 3/1/2014: catchlng all exceptions will break pytexthook on Windows XP
# CONFIG += noeh # Needed by pytexthook ONLY on windows xp orz
# include(../dllconfig.pri)
# include(../sys/sys.pri)
# include($$LIBDIR/winmaker/winmaker.pri)
# include($$LIBDIR/winmutex/winmutex.pri)

# config.pri
#  CONFIG(noeh) { # No Exception handler
#    message(CONFIG noeh)
#    QMAKE_CXXFLAGS          += /GR-
#    QMAKE_CXXFLAGS_RTTI_ON  -= /GR
#    QMAKE_CXXFLAGS_STL_ON        -= /EHsc
#    QMAKE_CXXFLAGS_EXCEPTIONS_ON -= /EHsc
#    CONFIG(dll) {
#      QMAKE_LFLAGS +=  /ENTRY:"DllMain"
#    }
#  }

set(vnrhost_src
  avl_p.h
  config.h
  hookman.h
  settings.h
  srv.h         
  srv_p.h   
  textthread.h
  textthread_p.h
  SettingManager.h
  hookman.cc
  main.cc
  pipe.cc
  textthread.cc
  ${PROJECT_SOURCE_DIR}/winmaker/winmaker.h
  ${PROJECT_SOURCE_DIR}/winmaker/winmaker.cc
  ${PROJECT_SOURCE_DIR}/winmutex/winmutex.h
  ${common_src}
)

source_group("common" FILES ${common_src})

add_library(vnrhost SHARED ${vnrhost_src})

set_target_properties(vnrhost PROPERTIES LINK_FLAGS /SUBSYSTEM:WINDOWS)

target_compile_options(vnrhost PRIVATE
  /GR-
  $<$<CONFIG:Release>:>
  $<$<CONFIG:Debug>:>
)

STRING(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})

target_link_libraries(vnrhost
  vnrsys
  ${WDK_HOME}/lib/wxp/i386/ntdll.lib
)

target_compile_definitions(vnrhost PRIVATE
)

install(TARGETS vnrhost RUNTIME
  DESTINATION .
  CONFIGURATIONS Release
)
