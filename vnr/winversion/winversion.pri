# winversion.pri
# 9/5/2014 jichi
win32 {
DEFINES += WITH_LIB_WINVERSION

LIBS += -lversion

DEPENDPATH += $$PWD

HEADERS += $$PWD/winversion.h
SOURCES += $$PWD/winversion.cc
}

# EOF
