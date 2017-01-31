#include ../Makefile.inc
#PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

APP_ROOTS = deadWrites threaded 
#all:  cct_client.so  deadspy_client.so cct_data_centric_client.so cct_client_mem_only.so cct_data_centric_client_tree_based.so deadWrites 

ALLOW_UNUSED_BUT_SET= -Wno-unused-but-set-variable
CCTLIB_TEST_FLAGS =  $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) -I$(SPARSEHASH_PATH)/include -I../src/ $(ALLOW_UNUSED_BUT_SET)

if OPT_USE_BOOST
	CCTLIB_TEST_FLAGS +=  -I$(BOOST_PATH)/include 
	BOOST_LD_FLAGS =  -L$(BOOST_PATH)/lib -Wl,-rpath $(BOOST_PATH)/lib 
	BOOST_LIBS =  -lboost_filesystem 
endif

LIBELF_LD_FLAGS= -L$(LIBELF_PATH)/lib -Wl,-rpath $(LIBELF_PATH)/lib
LIBELF_LIBS = -lelf
CLIENT_LD_FLAGS = $(BOOST_LD_FLAGS) $(LIBELF_LD_FLAGS)
CLIENT_LIBS = $(BOOST_LIBS) $(LIBELF_LIBS)


CCTLIB_SHADOW_BASED_LIBRARY=../src/$(OBJDIR)libcctlib$(LIB_SUFFIX)
CCTLIB_TREE_BASED_LIBRARY=../src/$(OBJDIR)libcctlib_tree_based$(LIB_SUFFIX)

include $(TOOLS_ROOT)/Config/makefile.default.rules

clean-local:
	rm -f $(OBJDIR)/*

