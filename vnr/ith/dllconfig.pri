# dllconfig.pri
# 8/9/2013 jichi
# For linking ITH injectable dlls.
# The dll is self-containd and Windows-independent.

CONFIG += dll noqt #noeh nosafeseh
CONFIG -= embed_manifest_dll # dynamically load dlls
win32 {
  CONFIG(eh): DEFINES += ITH_HAS_SEH # Do have exception handler in msvcrt.dll on Windows Vista and later
  CONFIG(noeh): DEFINES -= ITH_HAS_SEH # Do not have exception handler in msvcrt.dll on Windows XP and before
}
include(../../../config.pri)
#win32 {
#  CONFIG(noeh): include($$LIBDIR/winseh/winseh_safe.pri)
#}

# jichi 11/24/2013: Disable manual heap
DEFINES -= ITH_HAS_HEAP

# jichi 11/13/2011: disable swprinf warning
DEFINES += _CRT_NON_CONFORMING_SWPRINTFS

## Libraries

#LIBS        += -lkernel32 -luser32 -lgdi32
LIBS        += -L$$WDK7_HOME/lib/wxp/i386 -lntdll
LIBS        += $$WDK7_HOME/lib/crt/i386/msvcrt.lib   # Override msvcrt10
#LIBS        += -L$$WDK7_HOME/lib/crt/i386 -lmsvcrt
#QMAKE_LFLAGS += $$WDK7_HOME/lib/crt/i386/msvcrt.lib # This will leave runtime flags in the dll

#LIBS        += -L$$WDK8_HOME/lib/winv6.3/um/x86 -lntdll

HEADERS += $$PWD/dllconfig.h

# EOF
