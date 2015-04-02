# winseh_unsafe.pri
# 12/13/2013 jichi
#
# Need compile with /SAFESEH:NO
# See: http://stackoverflow.com/questions/19722308/exception-handler-not-called-in-c
#CONFIG += nosafeseh
win32 {
DEFINES += WITH_LIB_WINSEH

DEPENDPATH += $$PWD

HEADERS += $$PWD/winseh.h
SOURCES += \
    $$PWD/winseh.cc \
    $$PWD/winseh_unsafe.cc
}

# EOF
