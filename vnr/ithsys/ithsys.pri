# ithsys.pri
# 8/21/2013 jichi

DEFINES     += WITH_LIB_ITHSYS
LIBS        += -lithsys
DEPENDPATH  += $$PWD
HEADERS     += $$PWD/ithsys.h
#SOURCES     += $$PWD/ithsys.cc

#include($$LIBDIR/winddk/winddk.pri)
#LIBS    += -L$$WDK/lib/wxp/i386

# EOF
