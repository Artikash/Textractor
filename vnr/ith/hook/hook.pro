# hook.pro
# 8/9/2013 jichi
# Build vnrhook.dll for Windows 7+

CONFIG += eh eha # exception handler to catch all exceptions
#CONFIG += noeh # msvcrt on Windows XP does not has exception handler
include(../dllconfig.pri)
include(../sys/sys.pri)
include($$LIBDIR/disasm/disasm.pri)
include($$LIBDIR/memdbg/memdbg.pri)
include($$LIBDIR/ntinspect/ntinspect.pri)
#include($$LIBDIR/winseh/winseh_safe.pri)
include($$LIBDIR/winversion/winversion.pri)

# 9/27/2013: disable ITH this game engine, only for debugging purpose
#DEFINES += ITH_DISABLE_ENGINE

# jichi 9/22/2013: When ITH is on wine, mutex is needed to protect NtWriteFile
#DEFINES += ITH_WINE
#DEFINES += ITH_SYNC_PIPE

## Libraries

LIBS    += -lkernel32 -luser32 -lgdi32

## Sources

TEMPLATE = lib
TARGET   = vnrhook

#CONFIG += staticlib

HEADERS += \
  config.h \
  cli.h \
  hook.h \
  engine/engine.h \
  engine/hookdefs.h \
  engine/match.h \
  engine/pchooks.h \
  engine/util.h \
  tree/avl.h

SOURCES += \
  main.cc \
  rpc/pipe.cc \
  hijack/texthook.cc \
  engine/engine.cc \
  engine/match.cc \
  engine/pchooks.cc \
  engine/util.cc

#RC_FILE += vnrhook.rc
#OTHER_FILES += vnrhook.rc

# EOF
