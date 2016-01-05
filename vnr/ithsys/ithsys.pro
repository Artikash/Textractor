# ithsys.pro
# 8/21/2013 jichi
# Build ithsys.lib

#CONFIG += noqt noeh staticlib
CONFIG += noqt staticlib

include(../../../config.pri)
include($$LIBDIR/ntdll/ntdll.pri)

#LIBS += -L$$WDK7_HOME/lib/wxp/i386 -lntdll

#include($$LIBDIR/winddk/winddk.pri)
#LIBS    += -L$$WDK/lib/wxp/i386

# jichi 9/22/2013: When ITH is on wine, certain NT functions are replaced
#DEFINES += ITH_WINE

# jichi 7/12/2015: Always enable SEH
DEFINES += ITH_HAS_SEH

# jichi 11/24/2013: Disable manual heap
DEFINES -= ITH_HAS_HEAP

## Libraries

#INCLUDEPATH += $$ITH_HOME/include
#INCLUDEPATH += $$WDK7_HOME/inc/ddk

#LIBS        += -lgdi32 -luser32 -lkernel32
#LIBS        += -L$$WDK7_HOME/lib/wxp/i386 -lntdll
#LIBS        += $$WDK7_HOME/lib/crt/i386/msvcrt.lib   # Override msvcrt10

#DEFINES += ITH_HAS_CXX

#LIBS    += -lith_sys -lntdll
#LIBS    += -lith_tls -lntdll
#LIBS    += -lntoskrnl

DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

## Sources

TEMPLATE = lib
TARGET  = ithsys

HEADERS += ithsys.h
SOURCES += ithsys.cc

OTHER_FILES += ithsys.pri

# EOF
