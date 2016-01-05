// textthread_p.cc
// 6/6/2012 jichi

#include "texthook/textthread_p.h"
#include "texthook/texthook_p.h"
#include "winmutex/winmutex.h"
#include "wintimer/wintimer.h"
#include "host/textthread.h"
#include <QtCore/QRegExp>

//#define DEBUG "textthread_p.cc"
#include "sakurakit/skdebug.h"

enum { ITH_THREAD_NAME_CAPACITY = 0x200 }; // used internally by ITH

#define REPEAT_RX_1 "(.{2,})\\1+$" // The pattern has at least 2 bytes, and repeats at least once

/** Private class */

#define D_LOCK win_mutex_lock<D::mutex_type> d_lock(D::globalMutex) // Synchronized scope for accessing private data

class TextThreadDelegatePrivate
{
  SK_CLASS(TextThreadDelegatePrivate)
  SK_DISABLE_COPY(TextThreadDelegatePrivate)

public:
  typedef win_mutex<CRITICAL_SECTION> mutex_type;

  static mutex_type globalMutex; // Used only in public class. Because ITH is running in another single thread
  static int globalCapacity; // maximum text size
  static bool globalRemovesRepeat;
  static bool globalKeepsSpace;
  static bool globalWideCharacter;

  TextThread *t;
  WinTimer flushTimer; // as QTimer does not work with windows remote thread, use native WM_TIMER instead

  ulong signature; // buffered
  char sourceBuffer[ITH_THREAD_NAME_CAPACITY]; // buffered
  QString source; // buffered

  int bufferSize;
  int bufferCapacity;
  char *buffer;
  bool removesRepeat;

  QByteArray spaceBuffer;
  int spaceCount;

  struct Repeat
  {
    QRegExp rx; // cached
    char *buffer;   // repeated string
    int size;
    int pos; // >= 0, current pos of repeating string
    int offset; // offset of repeated string

    Repeat() : rx(REPEAT_RX_1), buffer(nullptr), size(0), pos(0), offset(-1) {}
    ~Repeat() { if (buffer) delete[] buffer; }

    void clear()
    {
      size = pos = 0;
      offset = -1;
    }

    bool isRepeating(const char *data, int len) const
    {
      if (!size || !buffer)
        return false;
      switch (len) {
      case 1: return pos < size && buffer[pos] == *data;
      case 2: return pos < size + 1 && buffer[pos] == data[0] && buffer[pos +1] == data[1];
      default:
        if (pos + len >= size)
          return false;
        for (int i = 0; i < len; i++)
          if (buffer[pos + i] != data[i])
            return false;
        return true;
      }
    }
  } repeat;

  // - Construction -
public:
  explicit TextThreadDelegatePrivate(TextThread *thread) : t(thread),
    bufferSize(0), bufferCapacity(globalCapacity), buffer(new char[globalCapacity]),
    spaceCount(0),
    removesRepeat(false)
  {
    signature = signatureOf(t);

    //size_t size =
    t->GetThreadString(sourceBuffer, ITH_THREAD_NAME_CAPACITY);
    source = sourceBuffer;
  }

  ~TextThreadDelegatePrivate() { delete[] buffer; }

  // - Properties -
public:
  //QString text() const  { return QString::fromLocal8Bit(buffer); }
  //ulong context() const { return t->GetThreadParameter()->retn; }
  //ulong subcontext() const { return t->GetThreadParameter()->spl; }

  //ulong processId() const { return t->PID(); }

  // - Actions -
public:
  void flush()
  {
    if (flushTimer.isActive())
      flushTimer.stop();
    if (bufferSize) {
      send();
      bufferSize = 0;
    }
    if (!spaceBuffer.isEmpty())
      spaceBuffer.clear();
    spaceCount = 0;
  }

  void syncGlobal()
  {
    if (bufferCapacity < globalCapacity) {
      delete[] buffer;
      bufferCapacity = globalCapacity;
      buffer = new char[bufferCapacity];
      if (repeat.buffer) {
        delete[] repeat.buffer;
        if (!removesRepeat)
          repeat.buffer = nullptr;
        else {
          char *largerBuffer = new char[bufferCapacity];
          if (repeat.size)
            qMemCopy(largerBuffer, repeat.buffer, repeat.size);
          repeat.buffer = largerBuffer;
        }
      }
      //bufferSize = repeatOffset = 0; // already reset in flush
      //if (removesRepeat)
      //  repeat.reset();
    }
    if (removesRepeat != globalRemovesRepeat) {
      removesRepeat = globalRemovesRepeat;
      if (removesRepeat)
        repeat.clear();
    }
  }

  void appendSpace()
  {
    flushTimer.start();
    spaceCount++;
    if (spaceBuffer.isEmpty())
      spaceBuffer.append(buffer, bufferSize);
    spaceBuffer.append(' ');
    if (globalWideCharacter)
      spaceBuffer.append('\0'); // L' ' = {'\x20', '\0'};
  }

  void append(const char *data, int len)
  {
    flushTimer.start();
    if (bufferSize < qMin(bufferCapacity, globalCapacity))
      switch (len) {
      case 1: buffer[bufferSize++] = *data; break;
      case 2: buffer[bufferSize++] = *data;
        if (bufferSize < bufferCapacity)
          buffer[bufferSize++] = data[1];
        break;
      default:
        {
          int diff = qMin(len, bufferCapacity - bufferSize);
          qMemCopy(buffer + bufferSize, data,  diff);
          bufferSize += diff;
        }
      }
    if (!spaceBuffer.isEmpty())
      spaceBuffer.append(data, len);
  }

  void appendRepeat(const char *data, int len)
  {
    if (bufferSize + len >= qMin(bufferCapacity, globalCapacity)) // overflow
      return;
    if (repeat.isRepeating(data, len)) {
      repeat.pos += len;
      if (repeat.pos >= repeat.size)
        repeat.pos = 0;
      return;
    }
    repeat.clear();

    append(data, len);

    if (bufferSize >= 6) { // at least 2 characters
      // Use fromLatin1 to prevent the data from being decoded
      QString t = QString::fromLatin1(buffer, bufferSize);
      repeat.offset = repeat.rx.indexIn(t);
      if (repeat.offset >= 0) {
        repeat.size = repeat.rx.cap(1).size();
        if (!repeat.buffer)
          repeat.buffer = new char[bufferCapacity];
        qMemCopy(repeat.buffer, buffer + repeat.offset, repeat.size);
        //bufferSize = repeat.offset repeat.size;
      }
    }
  }

private:
  void send()
  {
    int size;
    if (removesRepeat && repeat.offset >= 0 && repeat.size)
      size = repeat.offset + repeat.size;
    else
      size = bufferSize;
    if (!spaceBuffer.isEmpty() && spaceBuffer.size() !=  size)
      spaceBuffer.truncate(size + spaceCount);
    TextHookPrivate::sendData(
        QByteArray(buffer, size), spaceBuffer,
        signature, source);
  }

  static qint32 signatureOf(TextThread *t)
  {
    qint32 ret =
        (t->GetThreadParameter()->retn & 0xffff) |   // context
        (t->GetThreadParameter()->spl & 0xffff) << 16; // subcontext
    return ret ? ret : t->Addr();
  }

  //static QString sourceOf(TextThread *t);

public:
  static ulong contextOf(TextThread *t)
  { return t->GetThreadParameter()->retn; }

  static ulong subcontextOf(TextThread *t)
  { return t->GetThreadParameter()->spl; }
};

TextThreadDelegatePrivate::mutex_type TextThreadDelegatePrivate::globalMutex;
int TextThreadDelegatePrivate::globalCapacity = 512;
bool TextThreadDelegatePrivate::globalRemovesRepeat = false;
bool TextThreadDelegatePrivate::globalKeepsSpace = false;
bool TextThreadDelegatePrivate::globalWideCharacter = false;

//QString TextThreadDelegatePrivate::sourceOf(TextThread *t)
//{
//  Q_ASSERT(t);
//  QString ret;
//  enum { buf_size = 0x200 }; // 0x200 is used by ITH internally
//  wchar_t buf[buf_size];
//  ulong len = t->GetThreadString(buf, buf_size);
//  if (len)
//    ret = QString::fromWCharArray(buf, len);
//  return ret;
//}

/** Public class */

// - Constructions -

TextThreadDelegate::TextThreadDelegate(TextThread *t)
  : d_(new D(t))
{
  d_->flushTimer.setMethod(this, &Self::flush);
  d_->flushTimer.setSingleShot(true);
}

TextThreadDelegate::~TextThreadDelegate()
{
  if (d_->flushTimer.isActive())
    d_->flushTimer.stop();
  delete d_;
}

bool TextThreadDelegate::delegateOf(const Self *that) const
{
  Q_ASSERT(t);
  // Both have no context, and my subcontext is smaller
  return that
      && !D::contextOf(that->d_->t) && !D::contextOf(d_->t)
      && D::subcontextOf(that->d_->t) >= D::subcontextOf(d_->t)
      && ::strcmp(d_->sourceBuffer, that->d_->sourceBuffer) == 0
      && nameEquals("Malie");
}

// - Properties -

//TextThread *TextThreadDelegate::t() const { return d_->t; }
int TextThreadDelegate::threadNumber() const
{ return d_->t->Number(); }

qint32 TextThreadDelegate::signature() const
{ return d_->signature; }

QString TextThreadDelegate::name() const
{ return d_->source; }

bool TextThreadDelegate::nameEquals(const char *that) const
{ return !::strcmp(d_->sourceBuffer, that); }

int TextThreadDelegate::capacity() { return D::globalCapacity; }
void TextThreadDelegate::setCapacity(int value) { D::globalCapacity = value; }

bool TextThreadDelegate::removesRepeat() { return D::globalRemovesRepeat; }
void TextThreadDelegate::setRemovesRepeat(bool value) { D::globalRemovesRepeat = value; }

bool TextThreadDelegate::wideCharacter() { return D::globalWideCharacter; }
void TextThreadDelegate::setWideCharacter(bool value) { D::globalWideCharacter = value; }

bool TextThreadDelegate::keepsSpace() { return D::globalKeepsSpace; }
void TextThreadDelegate::setKeepsSpace(bool value) { D::globalKeepsSpace = value; }

void TextThreadDelegate::setInterval(int msecs)
{ d_->flushTimer.setInterval(msecs); }

void TextThreadDelegate::setParentWindow(WId winId)
{ d_->flushTimer.setParentWindow(winId); }

// - Actions -

void TextThreadDelegate::flush()
{
  D_LOCK;
  d_->flush();
  d_->syncGlobal();
}

void TextThreadDelegate::touch()
{
  D_LOCK;
  d_->flushTimer.start();
}

void TextThreadDelegate::append(const char *data, int len, bool space)
{
  D_LOCK;
  if (space && D::globalKeepsSpace)
    d_->appendSpace();
  if (data && len) {
    if (d_->removesRepeat)
      d_->appendRepeat(data, len);
    else
      d_->append(data, len);
  }
}

// EOF
/*
void TextThreadDelegate::append(const QByteArray &data)
{
  D::mutex_lock_type locker(D::mutex);

  d_->flushTimer.start();
  if (d_->buffer.size() <= D::capacity)
    d_->buffer.append(data);
}
void TextThreadDelegatePrivate::send()
{
#ifdef DEBUG
  qDebug()<< source()
          << t->Number()
          << t->PID()
          << QString::number(t->Addr(), 16)
          << QString::number(t->GetThreadParameter()->retn, 16)
          << QString::number(t->GetThreadParameter()->spl, 16)
          << QTextCodec::codecForName("SHIFT-JIS")->makeDecoder()->toUnicode(buffer);
#endif // DEBUG
}
*/
