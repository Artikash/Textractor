# wintimer.pri
# 7/20/2011 jichi
win32 {

DEFINES += WITH_LIB_WINTIMER

LIBS += -lkernel32 -luser32 -lwintimer

DEPENDPATH += $$PWD

HEADERS += \
  $$PWD/wintimer.h \
  $$PWD/wintimerbase.h

#SOURCES += \
#  $$PWD/wintimer.cc \
#  $$PWD/wintimerbase.cc
}

# EOF
