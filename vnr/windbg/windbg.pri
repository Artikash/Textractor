# windbg.pri
# 4/21/2014 jichi
win32 {

DEFINES += WITH_LIB_WINDBG

LIBS    += -lkernel32 -luser32

DEPENDPATH += $$PWD

HEADERS += \
  $$PWD/hijack.h \
  $$PWD/inject.h \
  $$PWD/util.h \
  $$PWD/unload.h \
  $$PWD/windbg_p.h \
  $$PWD/windbg.h

SOURCES += \
  $$PWD/hijack.cc \
  $$PWD/inject.cc \
  $$PWD/util.cc \
  $$PWD/unload.cc
}

# EOF
