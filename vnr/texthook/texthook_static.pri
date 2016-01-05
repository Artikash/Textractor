# texthook_static.pri
# 10/13/2011 jichi

include(../../../config.pri)
include($$LIBDIR/wintimer/wintimer.pri)

## Libraries

#DEFINES += _ITH_DEBUG_MEMORY

QT    += core

INCLUDEPATH += $$PWD
DEPENDPATH  += $$PWD

#WDK_HOME  = c:/winddk
#LIBS    += -L$$WDK_HOME/lib
# override folder must come before winddk/inc/api
#INCLUDEPATH += $$PWD/override/wdk/vc10
#INCLUDEPATH += $$WDK_HOME/include/api
#INCLUDEPATH += $$WDK_HOME/include/crt
#INCLUDEPATH += $$WDK_HOME/include/ddk

#ITH_HOME  = c:/dev/ith
#INCLUDEPATH += $$ITH_HOME/include
#LIBS    += -L$$ITH_HOME/lib
#LIBS    += -lITH_DLL #-lITH_SYS

#INCLUDEPATH += $$ITH_HOME/include
#LIBS        += -L$$ITH_HOME/lib -lihf

# Tell IHF not to override new operators, see: ith/mem.h
DEFINES += DEFAULT_MM

#LIBS  += -lmsvcrtd
#LIBS  += -lmsvcrt
#QMAKE_LFLAGS += /NODEFAULTLIB:msvcrt.lib /NODEFAULTLIB:msvcrtd.lib
DEFINES += _CRT_SECURE_NO_WARNINGS _CRT_NON_CONFORMING_SWPRINTFS

## Sources

#TEMPLATE = lib
#TARGET  = texthook
#CONFIG  += dll
#CONFIG += staticlib
#DEFINES += TEXTHOOK_BUILD_LIB
DEFINES += TEXTHOOK_STATIC_LIB

HEADERS += \
  $$PWD/ihf_p.h \
  $$PWD/ith_p.h \
  $$PWD/texthook_config.h \
  $$PWD/texthook.h \
  $$PWD/texthook_p.h \
  $$PWD/textthread_p.h \
  $$PWD/winapi_p.h

SOURCES += \
  $$PWD/ihf_p.cc \
  $$PWD/ith_p.cc \
  $$PWD/texthook.cc \
  $$PWD/textthread_p.cc \
  $$PWD/winapi_p.cc

#!wince*: LIBS += -lshell32
#RC_FILE += texthook.rc

OTHER_FILES += \
  $$PWD/texthook.pri \
  $$PWD/texthook.pro \
  $$PWD/texthook.rc

# EOF
