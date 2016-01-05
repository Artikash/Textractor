# hook.pro
# 8/9/2013 jichi
# Build vnrhook.dll for Windows 7+

# Exception handler to catch all exceptions
CONFIG += dll noqt eh eha # noeh nosafeseh

#CONFIG += noeh # msvcrt on Windows XP does not has exception handler
include(../../../config.pri)
include($$PLUGINDIR/ithsys/ithsys.pri)
include($$LIBDIR/disasm/disasm.pri)
include($$LIBDIR/memdbg/memdbg.pri)
include($$LIBDIR/ntdll/ntdll.pri)
include($$LIBDIR/ntinspect/ntinspect.pri)
include($$LIBDIR/winkey/winkey.pri)
#include($$LIBDIR/winseh/winseh_safe.pri)
include($$LIBDIR/winversion/winversion.pri)

# 9/27/2013: disable ITH this game engine, only for debugging purpose
#DEFINES += ITH_DISABLE_ENGINE

# jichi 9/22/2013: When ITH is on wine, mutex is needed to protect NtWriteFile
#DEFINES += ITH_WINE
#DEFINES += ITH_SYNC_PIPE

DEFINES += ITH_HAS_CRT ITH_HAS_SEH
DEFINES += MEMDBG_NO_STL NTINSPECT_NO_STL # disabled as not used

# jichi 11/24/2013: Disable manual heap
DEFINES -= ITH_HAS_HEAP

# jichi 11/13/2011: disable swprinf warning
DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

## Libraries

#LIBS        += -L$$WDK7_HOME/lib/wxp/i386 -lntdll
#LIBS        += $$WDK7_HOME/lib/crt/i386/msvcrt.lib   # Override msvcrt10

LIBS    += -lkernel32 -luser32 -lgdi32 #-lgdiplus

## Sources

TEMPLATE = lib
TARGET   = vnrhook

#CONFIG += staticlib

HEADERS += \
  include/const.h \
  include/defs.h \
  include/types.h \
  src/except.h \
  src/main.h \
  src/util/growl.h \
  src/util/util.h \
  src/tree/avl.h \
  src/hijack/texthook.h \
  src/engine/engine.h \
  src/engine/hookdefs.h \
  src/engine/match.h \
  src/engine/pchooks.h \
  src/engine/mono/funcinfo.h \
  src/engine/ppsspp/funcinfo.h

SOURCES += \
  src/main.cc \
  src/pipe.cc \
  src/util/util.cc \
  src/hijack/texthook.cc \
  src/engine/engine.cc \
  src/engine/match.cc \
  src/engine/pchooks.cc

#RC_FILE += vnrhook.rc
#OTHER_FILES += vnrhook.rc

OTHER_FILES += vnrhook.pri

# EOF
