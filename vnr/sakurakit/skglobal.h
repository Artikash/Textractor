#ifndef SKGLOBAL_H
#define SKGLOBAL_H

// skglobal.h
// 9/15/2012 jichi
// Similar to QtGlobal from Qt.
//
// Conventions:
// - All classes in sakurakit will be wrapped with SK_BEGIN_NAMESPACE and SK_END_NAMESPACE
// - All classes from sakurakit begin with Sk, such as SkClassA.
//   All functions from sakurakit begin with sk, such as skFuncA.

// Redefine SK_BEGIN_NAMESPACE/SK_END_NAMESPACE if need custom namespace
#ifndef SK_BEGIN_NAMESPACE
# define SK_BEGIN_NAMESPACE namespace Sk {
#endif
#ifndef SK_END_NAMESPACE
# define SK_END_NAMESPACE   } // namespace Sk
#endif

#define SK_FORWARD_DECLARE_CLASS(_name)   SK_BEGIN_NAMESPACE class _name;  SK_END_NAMESPACE
#define SK_FORWARD_DECLARE_STRUCT(_name)  SK_BEGIN_NAMESPACE struct _name; SK_END_NAMESPACE

SK_BEGIN_NAMESPACE
namespace Sk {}
SK_END_NAMESPACE

// In case Qt is not avaliable

//inline void sk_noop(void) {}
//
//template <typename T>
//inline void skUnused(T &x) { (void)x; }

#define SK_UNUSED(_var) (void)(_var)
#define SK_NOP          SK_UNUSED(0)

// same as Q_DISABLE_COPY and boost::noncopyable
// Disable when BOOST_PYTHON is enabled
#ifdef BOOST_PYTHON
# define SK_DISABLE_COPY(_class)
#else
# define SK_DISABLE_COPY(_class) \
  _class(const _class &); \
  _class &operator=(const _class &);
#endif // BOOST_PYTHON

// - Qt-like Pimp -

// Similar to QT_DECLARE_PRIVATE
#define SK_DECLARE_PRIVATE(_class) \
  friend class _class; \
  typedef _class D; \
  D *const d_;

// Similar to QT_DECLARE_PUBLIC
#define SK_DECLARE_PUBLIC(_class) \
  friend class _class; \
  typedef _class Q; \
  Q *const q_;

// - Self and Base -

#define SK_CLASS(_self) \
  typedef _self Self; \
  Self *self() const { return const_cast<Self *>(this); }

#define SK_EXTEND_CLASS(_self, _base) \
  SK_CLASS(_self) \
  typedef _base Base;

#define SK_UNDEF_POS    QPoint(-1, -1)
#define SK_UNDEF_POSF   QPointF(-1, -1)

// - QWidget Style Class for QSS -

// Read-only property
#define SK_STYLE_CLASS(_class) \
    Q_PROPERTY(QString class READ styleClass) \
  public: \
    QString styleClass() const { return #_class; } \
  private:

// Read-write property
#define SK_SYNTHESIZE_STYLE_CLASS \
    Q_PROPERTY(QString class READ styleClass WRITE setStyleClass) \
    QString styleClass_; \
  public: \
    QString styleClass() const { return styleClass_; } \
  public slots: \
    void seStyleClass(const QString &value) { styleClass_ = value; } \
  private:

#endif // SKGLOBAL_H
