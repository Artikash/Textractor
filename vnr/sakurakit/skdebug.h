#ifndef SKDEBUG_H
#define SKDEBUG_H

// skdebug.h
// 10/16/2011 jichi
// Macros for debug.

// Debug I/O
// - DPRINT: similar to fprintf, or KDPrint. Print to qDebug
// - DOUT: similar to std::cout. Print to qDebug
// - DERR: similar to std::cerr. Print to qWarning
#if defined(DEBUG) && !defined(SK_NO_DEBUG)

# if defined(QT_CORE_LIB) && !defined(SK_NO_QT)
#   include <QtCore/QDebug>
#   define DPRINT(...)    qDebug(QString("%1:%2:").arg((DEBUG), (__FUNCTION__)).toLocal8Bit().constData(), __VA_ARGS__)
#   define DOUT(_msg)     qDebug() << QString("%1:%2:").arg((DEBUG), (__FUNCTION__)).toLocal8Bit().constData() << _msg
#   define DERR(_msg)     qWarning() << QString("%1:%2:").arg((DEBUG), (__FUNCTION__)).toLocal8Bit().constData() << _msg
# else
#   include <iostream>
#   include <cstdio>
#   define DPRINT(...)    fprintf(stderr, DEBUG ":" __FUNCTION__ ": " __VA_ARGS__)
#   define DWPRINT(...)   fwprintf(stderr, DEBUG ":" __FUNCTION__ ": " __VA_ARGS__)
#   define DOUT(_msg)     std::cout << DEBUG << ":" << __FUNCTION__ << ": " << _msg << std::endl
#   define DWOUT(_msg)    std::wcout << DEBUG << ":" << __FUNCTION__ << ": " << _msg << std::endl
#   define DERR(_msg)     std::cerr << DEBUG << ":" << __FUNCTION__ << ": " << _msg << std::endl
#   define DWERR(_msg)    std::wcerr << DEBUG << ":" << __FUNCTION__ << ": " << _msg << std::endl
# endif // QT_CORE_LIB

#else // DEBUG

# define DPRINT(_dummy) (void)0
# define DOUT(_dummy)   (void)0
# define DERR(_dummy)   (void)0

//#ifdef _MSC_VER
//# pragma warning (disable:4390)   // C4390: empty controlled statement found: is this the intent?
//#endif // _MSC_VER

//#ifdef __GNUC__
//# pragma GCC diagnostic ignored "-Wempty-body" // empty body in an if or else statement
//#endif // __GNUC__

#endif // DEBUG

#endif // SKDEBUG_H
