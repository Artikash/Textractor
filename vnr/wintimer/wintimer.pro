# sys.pro
# 8/21/2013 jichi
# Build ITH_engine.dll

#CONFIG += noqt noeh staticlib
CONFIG += staticlib
include(../../../config.pri)

## Sources

TEMPLATE = lib
TARGET  = wintimer

HEADERS += \
  wintimer.h \
  wintimerbase.h

SOURCES += \
  wintimer.cc \
  wintimerbase.cc

# EOF
