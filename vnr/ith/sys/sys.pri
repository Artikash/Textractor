# sys.pri
# 8/21/2013 jichi

DEFINES     += WITH_LIB_ITH_SYS
LIBS        += -lvnrsys
DEPENDPATH  += $$PWD
HEADERS     += $$PWD/sys.h
#SOURCES     += $$PWD/sys.cc

#include($$LIBDIR/winddk/winddk.pri)
#LIBS    += -L$$WDK/lib/wxp/i386

# EOF
