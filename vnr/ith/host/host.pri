# host.pri
# 8/9/2011 jichi

DEFINES     += WITH_LIB_ITH_HOST

DEPENDPATH  += $$PWD

LIBS        += -lvnrhost

HEADERS += \
  $$PWD/avl_p.h \
  $$PWD/hookman.h \
  $$PWD/settings.h \
  $$PWD/srv.h \
  $$PWD/textthread.h \
  $$PWD/textthread_p.h

# EOF
