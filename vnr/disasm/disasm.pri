# disasm.pri
# 1/31/2012 jichi
win32 {

DEFINES     += WITH_LIB_DISASM
LIBS        += -ldisasm
DEPENDPATH  += $$PWD
HEADERS     += $$PWD/disasm.h
#SOURCES += $$PWD/disasm.cc

}

# EOF
