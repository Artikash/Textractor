# winkey.pri
# 7/20/2011 jichi
win32 {

DEFINES += WITH_LIB_WINKEY

LIBS += -luser32

DEPENDPATH += $$PWD

HEADERS += $$PWD/winkey.h
#SOURCES += $$PWD/winkey.cc
}

# EOF
