# winmutex.pri
# 3/8/2013 jichi

DEFINES += WITH_LIB_WINMUTEX

DEPENDPATH += $$PWD
#LIBS += -lkernel32 -luser32

HEADERS += \
  $$PWD/winmutex \
  $$PWD/winmutex.h

# EOF
