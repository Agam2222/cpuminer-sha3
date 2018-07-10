QT -= gui core

CONFIG += c++11 console
CONFIG -= app_bundle

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

LIBS += -ljansson -lcurl

CCFLAG += -Wnosign-compare -O2 -funroll-loops -march=native
QMAKE_CFLAGS += -Wno-sign-compare -Wno-format -funroll-loops
QMAKE_CXXFLAGS += -O2 -funroll-loops

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    uint256.cpp \
    sha3.c \
    atom-miner.c \
    util.c

HEADERS += \
    sha3.h \
    miner.h \
    cpuminer-config.h \
    compat.h \
    elist.h \
    uint256.h
