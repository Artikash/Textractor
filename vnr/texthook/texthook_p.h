#pragma once

// texthook_p.h
// 10/14/2011 jichi
// Internal header.
// Defines TextHook private data.

#include "texthook/texthook.h"
#include <QtCore/QHash>
#include <QtCore/QSet>

// - Private -

class TextHookPrivate
{
  SK_CLASS(TextHookPrivate)
  SK_DECLARE_PUBLIC(TextHook)

  static Self *instance_; // global instance

  bool enabled;
  QString source;
  QSet<ulong> pids;
  QHash<ulong, QString> hooks; // ITH hook code, indexed by pid

  explicit TextHookPrivate(Q *q)
    : q_(q), enabled(true), source(TEXTHOOK_DEFAULT_NAME) { instance_ = this; }

  ~TextHookPrivate() { instance_ = nullptr; }

public:
  static void sendData(const QByteArray &rawData, const QByteArray &renderedData, qint32 signature, const QString &name)
  {
    if (instance_ && instance_->q_->isEnabled())
      emit instance_->q_->dataReceived(rawData, renderedData, signature, name);
  }
};

// EOF
