# texthook.pri
# 10/13/2011 jichi

DEFINES += WITH_LIB_TEXTHOOK

INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

QT      += core
LIBS    += -ltexthook

HEADERS += \
  $$PWD/texthook_config.h

# texthook.h should not be in HEADERS, or it will be processed by moc
OTHER_FILES += \
  $$PWD/texthook.h \
  $$PWD/texthook.pro

# EOF
