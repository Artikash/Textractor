# ntinspect.pri
# 4/20/2014 jichi
win32 {

DEFINES += WITH_LIB_NTINSPECT

DEPENDPATH += $$PWD

HEADERS += $$PWD/ntinspect.h
SOURCES += $$PWD/ntinspect.cc

LIBS += -L$$WDK7_HOME/lib/wxp/i386 -lntdll

}

# EOF
