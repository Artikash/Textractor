# winseh_safe.pri
# 12/13/2013 jichi
#
# Need link with with SEH assembly
# See: http://stackoverflow.com/questions/12019689/custom-seh-handler-with-safeseh
# See: http://stackoverflow.com/questions/19722308/exception-handler-not-called-in-c
win32 {
#include(../../../config.pri)

# Disable buffer security check: http://msdn.microsoft.com/en-us/library/8dbf701c.aspx
#QMAKE_CXXFLAGS += /GS-

LIBS += safeseh.obj # compiled from safeseh.asm using ml -safeseh

DEFINES += WITH_LIB_WINSEH

DEPENDPATH += $$PWD

HEADERS += $$PWD/winseh.h
SOURCES += \
    $$PWD/winseh.cc \
    $$PWD/winseh_safe.cc

OTHER_FILES += \
    $$PWD/safeseh.asm \
    $$PWD/Makefile
}

# EOF
