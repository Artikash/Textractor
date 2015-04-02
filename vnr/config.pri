# config.pri
# 9/3/2011 jichi

## Locations

ROOTDIR = $$PWD
BUILDDIR = $$ROOTDIR/build

SRCDIR  = $$ROOTDIR/cpp
CONFDIR = $$SRCDIR/conf
LIBDIR  = $$SRCDIR/libs
COMDIR  = $$SRCDIR/coms
PLUGINDIR = $$SRCDIR/plugins
#SERVICEDIR = $$SRCDIR/services

DESTDIR         = $$BUILDDIR
#win32:  DESTDIR_TARGET  = $$BUILDDIR/release.win
#unix:   DESTDIR_TARGET  = $$BUILDDIR/release.unix
#mac:    DESTDIR_TARGET  = $$BUILDDIR/release.mac

LIBS            += -L$$DESTDIR
mac:  LIBS      += -F$$DESTDIR

INCLUDEPATH += \
  $$SRCDIR \
  $$LIBDIR \
  $$COMDIR \
  $$PLUGINDIR \
  $$SERVICEDIR

## Qt Translation

CODECFORTR = UTF-8
#CODECFORSRC = UTF-8    # there are sources in SJIS encoding

## Compiling options

# Windows
win32:  DEFINES += UNICODE  # force using UNICODE interface by default

# Mac
#CONFIG += x86 x86_64 ppc64
mac:    CONFIG -= ppc ppc64 # disable compiling fat architectures

# Enable C++11
win32:  QMAKE_CXXFLAGS += -Zc:auto
unix:   QMAKE_CXXFLAGS += -std=c++11
mac {
  # Enable TR1 such as tuple
  # Clang is required to take place of llvm gcc, which uses /usr/lib/libstdc++.dylib
  QMAKE_CXXFLAGS += -stdlib=libc++
  QMAKE_LFLAGS += -stdlib=libc++
}

# MSVC warnings
win32 {
  # Disable checked iterator and compiler warning.
  # SCL: http://msdn.microsoft.com/en-us/library/aa985896.aspx
  # SCL Warning: http://msdn.microsoft.com/en-us/library/aa985974.aspx
  # Performance comparison: http://askldjd.wordpress.com/2009/09/13/stl-performance-comparison-vc71-vc90-and-stlport/
  DEFINES += _SECURE_SCL=0 _SCL_SECURE_NO_WARNINGS

  # Disable CRT string function warnings
  DEFINES += _CRT_SECURE_NO_WARNINGS

  # Disable CRT posix warnings
  #DEFINES += _CRT_NONSTDC_NO_DEPRECATE

  QMAKE_CXXFLAGS += -wd4819 # ignore the warning on Japanese characters
}

## External Libraries

win32 {
  D3D_HOME      = "$$PROGRAMFILES/Microsoft DirectX SDK"
  DETOURS_HOME  = "$$PROGRAMFILES/Microsoft Research/Detours Express 3.0"
  #DEV_HOME      = c:/dev
  DEV_HOME      = z:/local/windows/developer
  BOOST_HOME    = $$DEV_HOME/boost/build
  #ITH_HOME      = $$DEV_HOME/ith
  MSIME_HOME    = $$DEV_HOME/msime
  #PYTHON_HOME  = $$ROOTDIR/../Python
  #PYTHON_HOME   = C:/Python
  PYTHON_HOME   = Z:/Local/Windows/Developer/Python
  PYSIDE_HOME   = $$PYTHON_HOME/Lib/site-packages/PySide
  QT_HOME       = c:/qt/4
  QT_SRC        = c:/qt
  SAPI_HOME     = "$$PROGRAMFILES/Microsoft Speech SDK 5.1"
  #WMSDK_HOME    = c:/wmsdk/wmpsdk9
  WDK7_HOME     = c:/winddk/7600.16385.1
  WDK8_HOME     = "$$PROGRAMFILES/Windows Kits/8.1"
  UTF8_HOME     = z:/users/jichi/opt/utf8
}
mac {
  MACPORTS_HOME = /opt/local
  BOOST_HOME    = $$MACPORTS_HOME
  DEV_HOME      = ${HOME}/opt
  #ITH_HOME      = ${HOME}/opt/ith
  MSIME_HOME    = $$DEV_HOME/msime
  PYSIDE_HOME   = $$MACPORTS_HOME
  PYTHON_HOME   = $$MACPORTS_HOME/Library/Frameworks/Python.framework/Versions/Current
  #QT_HOME      = ${HOME}/opt/qt
  QT_HOME       = $$MACPORTS_HOME
  QT_SRC        = ${HOME}/src
  UTF8_HOME     = $$DEV_HOME/utf8
}

INCLUDEPATH     += $$BOOST_HOME $$BOOST_HOME/include
LIBS            += -L$$BOOST_HOME/lib

# Disable automatically linking with boost silently
# See: http://www.boost.org/doc/libs/1_56_0/boost/config/user.hpp
DEFINES += BOOST_ALL_NO_LIB
mac: BOOST_VARIANT = -mt

## Config

CONFIG(release) {
  message(CONFIG release)
  #DEFINES += QT_NO_DEBUG_OUTPUT QT_NO_WARNING_OUTPUT
}

CONFIG(noqt) {
  message(CONFIG noqt)
  CONFIG += noqtcore noqtgui
  CONFIG -= qt
}
CONFIG(noqtcore) {
  message(CONFIG noqtcore)
  QT    -= core
  LIBS  -= -lQtCore
}
CONFIG(noqtgui) {
  message(CONFIG noqtgui)
  QT    -= gui
  LIBS  -= -lQtGui
  mac: CONFIG -= app_bundle
}

win32 {
  CONFIG(nocrt) { # No runtime CRT. Use -MT for static linking.
    message(CONFIG nocrt)
    QMAKE_CFLAGS                -= -MD -MDd
    QMAKE_CFLAGS_DEBUG          -= -MD -MDd
    QMAKE_CFLAGS_RELEASE        -= -MD -MDd
    QMAKE_CFLAGS_RELEASE_WITH_DEBUGINFO -= -MD -MDd
    QMAKE_CXXFLAGS              -= -MD -MDd
    QMAKE_CXXFLAGS_DEBUG        -= -MD -MDd
    QMAKE_CXXFLAGS_RELEASE      -= -MD -MDd
    QMAKE_CXXFLAGS_RELEASE_WITH_DEBUGINFO -= -MD -MDd
    #QMAKE_LFLAGS                += -NODEFAULTLIB:msvcrt.lib \
    #                               -NODEFAULTLIB:msvcrtd.lib
  }

  # http://social.msdn.microsoft.com/Forums/vstudio/en-US/96c906d9-de1d-4ace-af37-71169617b6ff/destructors-and-seh
  CONFIG(eha) { # Catch all exceptions
    message(CONFIG eha)
    QMAKE_CXXFLAGS_STL_ON        -= -EHsc
    QMAKE_CXXFLAGS_EXCEPTIONS_ON -= -EHsc
    QMAKE_CXXFLAGS_STL_ON        += -EHa
    QMAKE_CXXFLAGS_EXCEPTIONS_ON += -EHa
  }

  CONFIG(noeh) { # No Exception handler
    message(CONFIG noeh)
    #CONFIG -= rtti #-exceptions -stl
    QMAKE_CXXFLAGS          += /GR-
    QMAKE_CXXFLAGS_RTTI_ON  -= -GR

    QMAKE_CXXFLAGS_STL_ON        -= -EHsc
    QMAKE_CXXFLAGS_EXCEPTIONS_ON -= -EHsc

    CONFIG(dll) {
      QMAKE_LFLAGS +=  /ENTRY:"DllMain"
    }
  }

  CONFIG(nosafeseh) { # No Exception handler
    message(CONFIG nosafeseh)

    # Disable SafeSEH table
    # http://stackoverflow.com/questions/19722308/exception-handler-not-called-in-c/20344222
    # Alternative way: Register handler using MASM
    # http://stackoverflow.com/questions/12019689/custom-seh-handler-with-safeseh
    QMAKE_LFLAGS += -safeseh:no
  }
}

CONFIG(gdb) {
  message(CONFIG gdb)
  QMAKE_CXXFLAGS += -g -ggdb
}

CONFIG(lldb) {
  message(CONFIG lldb)
  QMAKE_CXXFLAGS += -g #-glldb
}

CONFIG(qmlplugin) {
  message(CONFIG qmlplugin)
  QT += core declarative
  win32: CONFIG  += dll
}

CONFIG(pysideplugin) {
  message(CONFIG pysideplugin)
  CONFIG += pyplugin shiboken
  QT += core

  LIBS += -L$$PYSIDE_HOME -lpyside-python2.7
  INCLUDEPATH += \
    $$PYSIDE_HOME/include/PySide \
    $$PYSIDE_HOME/include/PySide-2.7 \
    $$PYSIDE_HOME/include \
    $$PYSIDE_HOME/include/PySide/QtCore \
    $$PYSIDE_HOME/include/PySide/QtGui \
    $$QT_HOME/include/QtGui # needed by pyside qtcore
}

CONFIG(shiboken) {
  message(CONFIG shiboken)

  LIBS += -L$$PYSIDE_HOME -lshiboken-python2.7
  INCLUDEPATH += \
    $$PYSIDE_HOME/include/shiboken \
    $$PYSIDE_HOME/include/shiboken-2.7

  # Ignore warnings from Shiboken and PySide
  mac {
    QMAKE_CXXFLAGS_WARN_ON += \
        -Wno-header-guard \
        -Wno-mismatched-tags   \
        -Wno-missing-field-initializers \
        -Wno-unused-parameter
  }
  win32 {
    # QMAKE_CXXFLAGS_WARN_ON does not work on windows
    #
    #ifdef _MSC_VER
    # pragma warning (disable:4099)   // C4099: mix class and struct
    # pragma warning (disable:4100)   // C4100: unreferenced parametter
    # pragma warning (disable:4244)   // C4244: conversion lost of data
    # pragma warning (disable:4390)   // C4390: empty controlled statement
    # pragma warning (disable:4522)   // C4522: multiple assignment operators
    # pragma warning (disable:4800)   // C4800: forcing value to bool
    #endif // _MSC_VER
    QMAKE_CXXFLAGS += -wd4099 -wd4100 -wd4244 -wd4390 -wd4522 -wd4800
  }
}

CONFIG(pyplugin) {
  message(CONFIG pyplugin)
  INCLUDEPATH   += $$PYTHON_HOME/include/python2.7 $$PYTHON_HOME/include

  unix:  LIBS   += -L$$PYTHON_HOME/lib -lpython2.7
  win32: LIBS   += -L$$PYTHON_HOME/libs -lpython27

  unix:  QMAKE_EXTENSION_SHLIB = so
  win32: QMAKE_EXTENSION_SHLIB = pyd
  win32: CONFIG += dll
}

CONFIG(qt) {
  message(CONFIG qt)
  INCLUDEPATH += $$QT_SRC $$QT_SRC/qt # always allow access to Qt source code

  # Clang: Disable warning while processing Qt library headers
  # http://stackoverflow.com/questions/17846909/how-can-i-stop-warnings-about-unused-private-fields
  mac {
    QMAKE_CXXFLAGS_WARN_ON += -Wno-deprecated-register  # register storage class specifier is deprecated
    QMAKE_CXXFLAGS_WARN_ON += -Wno-unused-private-field # private field 'type' is not used in qmime.h
  }
}

# EOF

## Debug

#include($$ROOTDIR/lib/debug/debug.pri)

## Deploy

#DEFINES += VERSION=\\\"$$VERSION\\\"

## IDs

# Azure Market Key: https://datamarket.azure.com/account/datasets
#DEFINES += CONFIG_AZURE_ID=\\\"tuSmXew4CSnnGaX0vZyYdNLCrlInvAUepCX6p5l5THc=\\\"

# Yahoo!JAPAN AppID: https://e.developer.yahoo.co.jp/dashboard/
#DEFINES += CONFIG_YAHOO_ID=\\\"mRr.UCWxg65ZTZTR_Mz0OTtj3sJ7xa5K66ZOGp55cgJsIDDeaB6e1LDY1NpEZ_AfZA--\\\"

## Deploy
# See: http://wiki.maemo.org/Packaging_a_Qt_application
# See: http://www.developer.nokia.com/Community/Wiki/Creating_Debian_packages_for_Maemo_5_Qt_applications_and_showing_in_the_application_menu
# See: https://wiki.kubuntu.org/PackagingGuide/QtApplication

#QMLDIR=$$DESTDIR/qml
#LUADIR=$$DESTDIR/lua
#DOCDIR=$$DESTDIR/doc
#TABLEDIR=$$DESTDIR/table
#IMAGEDIR=$$DESTDIR/images
#JSFDIR=$$DESTDIR/jsf
#AVATARDIR=$$DESTDIR/avatars

#unix:!mac {
#    isEmpty(PREFIX): PREFIX = /usr
#    BINDIR = $$PREFIX/bin
#    DATADIR = $$PREFIX/share
#}
#mac {
#    isEmpty(PREFIX): PREFIX = /opt/annot
#    BINDIR = $$PREFIX/bin
#    DATADIR = $$PREFIX/share
#}
#
#!win32 {
#  DEFINES += \
#    BINDIR=\\\"$$BINDIR\\\" \
#    DATADIR=\\\"$$DATADIR\\\"
#}
#DEFINES += \
#    AVATARDIR=\\\"$$AVATARDIR\\\" \
#    DOCDIR=\\\"$$DOCDIR\\\" \
#    TABLEDIR=\\\"$$TABLEDIR\\\" \
#    IMAGEDIR=\\\"$$IMAGDIR\\\" \
#    LUADIR=\\\"$$LUADIR\\\" \
#    JSFDIR=\\\"$$JSFDIR\\\"

## External libraries

#win32 {
#    DEV_HOME            = c:/dev
#    #DEV_HOME            = B:/Developer
#    QT_HOME             = c:/qt/qt4
#    QT_SRC              = c:/qt
#    QT5_HOME            = c:/qt/qt5
#    QT5_SRC             = c:/qt
#    #VLC_HOME            = "c:/Program Files/VideoLAN/VLC/sdk"
#    VLC_HOME            = $$DEV_HOME/vlc
#    VLC_SRC             = $$VLC_HOME/src
#    #WSF_HOME            = $$DEV_HOME/wso2
#    #CDIO_HOME          = $$DEV_HOME/cdio
#    #FFMPEG_HOME         = $$DEV_HOME/ffmpeg
#    GPAC_HOME           = $$DEV_HOME/gpac
#    MP4V2_HOME          = $$DEV_HOME/mp4v2
#    LIVE_HOME           = $$DEV_HOME/live
#    POPPLER_HOME        = $$DEV_HOME/poppler
#    BOOST_HOME          = $$DEV_HOME/boost
#    GSOAP_HOME          = $$DEV_HOME/gsoap
#    GSOAP_SRC           = $$DEV_HOME/gsoap/src
#    ZDEV_HOME           = $$DEV_HOME/zlib
#    LUA_HOME            = $$DEV_HOME/lua
#    FREETYPE_HOME       = $$DEV_HOME/freetype
#    FONTCONFIG_HOME     = $$DEV_HOME/fontconfig
#    MECAB_HOME          = $$DEV_HOME/mecab
#    #LUA_VERSION = 52
#    #LUA_VERSION = 5.1
#    LUA_VERSION =
#
#    ITH_HOME            = $$DEV_HOME/ith
#
#    WDK_HOME            = c:/winddk/current
#
#    INCLUDEPATH        += $$DEV_HOME/inttypes/include
#
#    INCLUDEPATH        += $$ITH_HOME/include
#    LIBS               += -L$$ITH_HOME/lib
#
#    # wdk/inc/api/sal.h MUST be removed.
#    # See:  http://stackoverflow.com/questions/1356653/multiple-compiling-errors-with-basic-c-application-on-vs2010-beta-1
#    # Select WinXP x86
#    INCLUDEPATH        += $$WDK_HOME/inc
#    LIBS               += -L$$WDK_HOME/lib/wxp/i386
#}
#
#unix {
#    X11_HOME            = /usr/X11
#    QT_HOME             = /usr/share/qt4
#    QT_SRC              =
#    VLC_HOME            = /usr
#    VLC_SRC             = ${HOME}/opt/src
#    #WSF_HOME            = ${HOME}/opt/wso2/wsf
#    #CDIO_HOME          = /usr
#    #FFMPEG_HOME         = /usr
#    MECAB_HOME          = /usr
#    GPAC_HOME           = /usr
#    MP4V2_HOME          = /usr
#    LIVE_HOME           = /usr
#    POPPLER_HOME        = ${HOME}/opt/poppler
#    BOOST_HOME          = /usr
#    GSOAP_HOME          = ${HOME}/opt/gsoap
#    GSOAP_SRC           = ${HOME}/opt/src/gsoap
#    LUA_HOME            = /usr
#    ZDEV_HOME           = /usr
#    FREETYPE_HOME       = $$X11_HOME
#    FONTCONFIG_HOME     = $$X11_HOME
#    LUA_VERSION = 5.1
#}
#
#mac {
#    SDK_HOME            = /Developer/SDKs/MacOSX10.7.sdk
#    X11_HOME            = $$SDK_HOME/usr/X11
#    MACPORTS_HOME       = /opt/local
#    QT_HOME             = ${HOME}/opt/qt
#    QT_SRC              = ${HOME}/opt/src
#    QT5_HOME            = ${HOME}/opt/qt5
#    QT5_SRC             = ${HOME}/opt/src
#    #VLC_HOME            = ${HOME}/opt/vlc
#    VLC_HOME            = /Applications/VLC.app/Contents/MacOS
#    VLC_SRC             = ${HOME}/opt/src
#    #WSF_HOME           = ${HOME}/opt/wso2/wsf
#    #CDIO_HOME          = ${HOME}/opt/libcdio
#    #FFMPEG_HOME         = $$MACPORTS_HOME
#    GPAC_HOME           = ${HOME}/opt/gpac
#    MP4V2_HOME          = $$MACPORTS_HOME
#    MECAB_HOME          = $$MACPORTS_HOME
#    LIVE_HOME           = ${HOME}/opt/live
#    POPPLER_HOME        = ${HOME}/opt/poppler
#    BOOST_HOME          = $$MACPORTS_HOME
#    GSOAP_HOME          = ${HOME}/opt/gsoap
#    GSOAP_SRC           = ${HOME}/opt/src/gsoap
#    ZDEV_HOME           = $$SDK_HOME/usr
#    FREETYPE_HOME       = $$X11_HOME
#    FONTCONFIG_HOME     = $$X11_HOME
#    #LUA_HOME            = ${HOME}/opt/lua
#    LUA_HOME            = $$MACPORTS_HOME
#    #LUA_VERSION = 52
#    LUA_VERSION =
#}
#
#INCLUDEPATH     += $$QT_SRC/qt/src
##INCLUDEPATH     += $$QT5_SRC/qt/src
#
#INCLUDEPATH     += $$VLC_HOME/include
#INCLUDEPATH     += $$VLC_HOME/include/vlc/plugins
##INCLUDEPATH     += $$VLC_SRC/include
#LIBS            += -L$$VLC_HOME/lib
##INCLUDEPATH     += $$WSF_HOME/include
##LIBS            += -L$$WSF_HOME/lib
##INCLUDEPATH     += $$CDIO_HOME/include
##LIBS            += -L$$CDIO_HOME/lib
##INCLUDEPATH     += $$POPPLER_HOME/include/poppler/qt4
##LIBS            += -L$$POPPLER_HOME/lib
#INCLUDEPATH     += $$BOOST_HOME/include
#LIBS            += -L$$BOOST_HOME/lib
#INCLUDEPATH     += $$GSOAP_HOME/include
##LIBS            += -L$$GSOAP_HOME/lib
#INCLUDEPATH     += $$ZDEV_HOME/include
#LIBS            += -L$$ZDEV_HOME/lib
#INCLUDEPATH     += $$MECAB_HOME/include
#LIBS            += -L$$MECAB_HOME/lib
#INCLUDEPATH     += $$FREETYPE_HOME/include \
#                   $$FREETYPE_HOME/include/freetype2
#LIBS            += -L$$FREETYPE_HOME/lib
#INCLUDEPATH     += $$FONTCONFIG_HOME/include
#LIBS            += -L$$FONTCONFIG_HOME/lib
#INCLUDEPATH     += $$LUA_HOME/include \
#                   $$LUA_HOME/include/lua$$LUA_VERSION
#LIBS            += -L$$LUA_HOME/lib
##INCLUDEPATH     += $$FFMPEG_HOME/include
##LIBS            += -L$$FFMPEG_HOME/lib
##INCLUDEPATH     += $$GPAC_HOME/include
##LIBS            += -L$$GPAC_HOME/lib
##INCLUDEPATH     += $$MP4V2_HOME/include
##LIBS            += -L$$MP4V2_HOME/lib
##INCLUDEPATH     += \
##    $$LIVE_HOME/BasicUsageEnvironment/include \
##    $$LIVE_HOME/UsageEnvironment/include \
##    $$LIVE_HOME/groupsock/include \
##    $$LIVE_HOME/liveMedia/include
#    #$$LIVE_HOME/BasicUsageEnvironment $$LIVE_HOME/BasicUsageEnvironment/include \
#    #$$LIVE_HOME/UsageEnvironment $$LIVE_HOME/UsageEnvironment/include \
#    #$$LIVE_HOME/groupsock $$LIVE_HOME/groupsock/include \
#    #$$LIVE_HOME/liveMedia $$LIVE_HOME/liveMedia/include
##LIBS            += \
##    -L$$LIVE_HOME/BasicUsageEnvironment \
##    -L$$LIVE_HOME/UsageEnvironment \
##    -L$$LIVE_HOME/groupsock \
##    -L$$LIVE_HOME/liveMedia
#
#mac: INCLUDEPATH += $$SDK_HOME/usr/include

#
# assistant.pro - Qt 4.7.3
#
#include(../../../shared/fontpanel/fontpanel.pri)
#TEMPLATE = app
#LANGUAGE = C++
#TARGET = assistant
#contains(QT_CONFIG, webkit):QT += webkit
#CONFIG += qt \
#    warn_on \
#    help
#QT += network
#PROJECTNAME = Assistant
#DESTDIR = ../../../../bin
#target.path = $$[QT_INSTALL_BINS]
#INSTALLS += target
#DEPENDPATH += ../shared
#
## ## Work around a qmake issue when statically linking to
## ## not-yet-installed plugins
#QMAKE_LIBDIR += $$QT_BUILD_TREE/plugins/sqldrivers
#HEADERS += aboutdialog.h \
#    bookmarkdialog.h \
#    bookmarkfiltermodel.h \
#    bookmarkitem.h \
#    bookmarkmanager.h \
#    bookmarkmanagerwidget.h \
#    bookmarkmodel.h \
#    centralwidget.h \
#    cmdlineparser.h \
#    contentwindow.h \
#    findwidget.h \
#    filternamedialog.h \
#    helpenginewrapper.h \
#    helpviewer.h \
#    indexwindow.h \
#    installdialog.h \
#    mainwindow.h \
#    preferencesdialog.h \
#    qtdocinstaller.h \
#    remotecontrol.h \
#    searchwidget.h \
#    topicchooser.h \
#    tracer.h \
#    xbelsupport.h \
#    ../shared/collectionconfiguration.h
#contains(QT_CONFIG, webkit) {
#    HEADERS += helpviewer_qwv.h
#} else {
#   HEADERS += helpviewer_qtb.h
# }
#win32:HEADERS += remotecontrol_win.h
#
#SOURCES += aboutdialog.cpp \
#    bookmarkdialog.cpp \
#    bookmarkfiltermodel.cpp \
#    bookmarkitem.cpp \
#    bookmarkmanager.cpp \
#    bookmarkmanagerwidget.cpp \
#    bookmarkmodel.cpp \
#    centralwidget.cpp \
#    cmdlineparser.cpp \
#    contentwindow.cpp \
#    findwidget.cpp \
#    filternamedialog.cpp \
#    helpenginewrapper.cpp \
#    helpviewer.cpp \
#    indexwindow.cpp \
#    installdialog.cpp \
#    main.cpp \
#    mainwindow.cpp \
#    preferencesdialog.cpp \
#    qtdocinstaller.cpp \
#    remotecontrol.cpp \
#    searchwidget.cpp \
#    topicchooser.cpp \
#    xbelsupport.cpp \
#    ../shared/collectionconfiguration.cpp
# contains(QT_CONFIG, webkit) {
#    SOURCES += helpviewer_qwv.cpp
#} else {
#    SOURCES += helpviewer_qtb.cpp
#}
#
#FORMS += bookmarkdialog.ui \
#    bookmarkmanagerwidget.ui \
#    bookmarkwidget.ui \
#    filternamedialog.ui \
#    installdialog.ui \
#    preferencesdialog.ui \
#    topicchooser.ui
#
#RESOURCES += assistant.qrc \
#    assistant_images.qrc
#
#win32 {
#    !wince*:LIBS += -lshell32
#    RC_FILE = assistant.rc
#}
#
#mac {
#    ICON = assistant.icns
#    TARGET = Assistant
#    QMAKE_INFO_PLIST = Info_mac.plist
#}
#
#contains(CONFIG, static): {
#    SQLPLUGINS = $$unique(sql-plugins)
#    contains(SQLPLUGINS, sqlite): {
#        QTPLUGIN += qsqlite
#        DEFINES += USE_STATIC_SQLITE_PLUGIN
#    }
#}
