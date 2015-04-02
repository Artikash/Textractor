# sys.pro
# 8/21/2013 jichi
# Build vnrsys.lib

CONFIG += noqt noeh staticlib

include(../../../../config.pri)
include($$LIBDIR/ntdll/ntdll.pri)

#include($$LIBDIR/winddk/winddk.pri)
#LIBS    += -L$$WDK/lib/wxp/i386

# jichi 9/22/2013: When ITH is on wine, certain NT functions are replaced
#DEFINES += ITH_WINE

# jichi 9/14/2013: Windows XP's msvnrt does not have except handler
DEFINES -= ITH_HAS_SEH

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
TARGET  = vnrsys

HEADERS += sys.h
SOURCES += sys.cc

OTHER_FILES += sys.pri

# EOF
