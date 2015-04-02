# sys.pro
# 8/21/2013 jichi
# Build ITH_engine.dll

CONFIG += noqt noeh staticlib
include(../../../config.pri)

## Sources

TEMPLATE = lib
TARGET  = disasm

HEADERS += disasm.h
SOURCES += disasm.cc

# EOF
