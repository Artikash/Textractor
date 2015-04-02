# ith.pro
# 10/13/2011 jichi

TEMPLATE = subdirs

# The order is important!
SUBDIRS += \
  sys \
  hook hookxp \
  host

OTHER_FILES += dllconfig.pri

include(common/common.pri)  # not used
include(import/mono/mono.pri)  # not used
include(import/ppsspp/ppsspp.pri)  # not used

# EOF
