# ntinspect.pri
# 4/20/2014 jichi
win32 {

DEFINES += WITH_LIB_MEMDBG

DEPENDPATH += $$PWD

HEADERS += \
  $$PWD/memdbg.h \
  $$PWD/memsearch.h

SOURCES += \
  $$PWD/memsearch.cc
}

# EOF
