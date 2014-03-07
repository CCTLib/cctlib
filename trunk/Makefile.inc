CXX = g++

DEBUG=1

#ifndef  SPARSEHASH_PATH
#$(echo "SPARSEHASH_PATH NOT SET!!")
#endif
#ifndef  PIN_PATH
#$(echo "PIN_PATH NOT SET!!")
#endif
#ifndef  BOOST_PATH
#$(echo "BOOST_PATH NOT SET!!")
#endif

ifeq ($(DEBUG),1)
CFLAGS = -c -g -O0 -Wno-deprecated -Wall -Wno-unknown-pragmas   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX
LINKFLAGS = -g -O0 -Wl,--hash-style=sysv -shared -Wl,-Bsymbolic -Wl,--version-script=$(PIN_PATH)/source/include/pin/pintool.ver
else
CFLAGS = -c -g -O3 -Wno-deprecated -Wall  -Wno-unknown-pragmas  -fomit-frame-pointer -fno-stack-protector -fno-strict-aliasing -DNDEBUG -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX
LINKFLAGS = -g -O3 -Wl,--hash-style=sysv -shared -Wl,-Bsymbolic -Wl,--version-script=$(PIN_PATH)/source/include/pin/pintool.ver
endif

INCLUDES = -I$(BOOST_PATH)/include -I$(SPARSEHASH_PATH)/src -I$(PIN_PATH)/extras/xed2-intel64/include -I$(PIN_PATH)/extras/components/include -I$(PIN_PATH)/source/include -I$(PIN_PATH)/source/include/pin/gen -I$(PIN_PATH)/source/include/pin
LIBRARIES = -L$(BOOST_PATH)/lib -L$(PIN_PATH)/extras/xed2-intel64/lib -L$(PIN_PATH)/intel64/lib -L$(PIN_PATH)/intel64/lib-ext -L$(PIN_PATH)/intel64/runtime/cpplibs -lpin -lxed -ldwarf -lelf -ldl -lboost_filesystem

