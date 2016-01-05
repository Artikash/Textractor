# sakurakit.pri
# 6/28/2011 jichi
#
# config:
# - sakurakit_qml
# - sakurakit_gui
# - sakurakit_widgets

DEFINES += WITH_LIB_SAKURAKIT
DEPENDPATH += $$PWD

#QT += core
HEADERS += \
  $$PWD/skautorun.h \
  $$PWD/skdebug.h \
  $$PWD/skglobal.h \
  $$PWD/skhash.h

#CONFIG(sakurakit_gui) {
#  DEFINES += SK_ENABLE_GUI
#  QT += gui
#  HEADERS += \
#    $$PWD/skuiutil.h
#
#  CONFIG(sakurakit_qml) {
#    DEFINES += SK_ENABLE_QML
#    QT += qml quick
#    HEADERS += \
#      $$PWD/skdraggablequickview.h
#    SOURCES += \
#      $$PWD/skdraggablequickview.cc
#  }
#
#  CONFIG(sakurakit_widgets) {
#    DEFINES += SK_ENABLE_WIDGETS
#    QT += widgets
#    HEADERS += \
#      $$PWD/skdraggabledialog.h \
#      $$PWD/skdraggablemainwindow.h \
#      $$PWD/skdraggablewidget.h \
#      $$PWD/skpushbutton.h \
#      $$PWD/sksystemtrayicon.h \
#      $$PWD/sktoolbutton.h \
#      $$PWD/skwindowcontainer.h
#    SOURCES += \
#      $$PWD/skdraggablewidget.cc \
#      $$PWD/skpushbutton.cc \
#      $$PWD/sktoolbutton.cc \
#      $$PWD/skwindowcontainer.cc \
#      $$PWD/skdraggabledialog.cc \
#      $$PWD/skdraggablemainwindow.cc
#
#    CONFIG(sakurakit_qml) {
#      HEADERS += \
#        $$PWD/skquickwidget.h
#      SOURCES += \
#        $$PWD/skquickwidget.cc
#    }
#  }
#}

# EOF
