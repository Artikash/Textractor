# texthook.pro
# 10/13/2011 jichi
# Build ith texthook dll.

CONFIG += noqtgui dll #eha # eha will catch all exceptions, but does not work on Windows XP
include(../../../config.pri)
include(host/host.pri)
include($$LIBDIR/winmutex/winmutex.pri)
include($$LIBDIR/wintimer/wintimer.pri)
include($$LIBDIR/windbg/windbg.pri)
#include($$LIBDIR/winmaker/winmaker.pri)

# TODO: Get rid of dependence on ITHSYS and NT APIs
include($$PLUGINDIR/vnrhook/vnrhook.pri)
include($$PLUGINDIR/ithsys/ithsys.pri)
LIBS += -L$$WDK7_HOME/lib/wxp/i386 -lntdll

DEFINES += ITH_HAS_CRT # Use native CRT

# TODO: Get rid of dependence on msvc's swprintf
DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

## Libraries

QT += core
QT -= gui

## Sources

TEMPLATE = lib
TARGET  = texthook

#CONFIG += staticlib
DEFINES += TEXTHOOK_BUILD_LIB

HEADERS += \
  growl.h \
  ihf_p.h \
  ith_p.h \
  texthook_config.h \
  texthook.h \
  texthook_p.h \
  textthread_p.h \
  winapi_p.h

SOURCES += \
  ihf_p.cc \
  ith_p.cc \
  texthook.cc \
  textthread_p.cc \
  winapi_p.cc

#!wince*: LIBS += -lshell32
#RC_FILE += texthook.rc

OTHER_FILES += \
  texthook.pri \
  texthook_static.pri \
  texthook.rc

# EOF
