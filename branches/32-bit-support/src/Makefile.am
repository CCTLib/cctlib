#include ../Makefile.inc
#all:  libcctlib.a libcctlib_tree_based.a
PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config


LIB_ROOTS=libcctlib libcctlib_tree_based

# This object file may be used later on to build dlls, so it needs to be compiled with the DLL_CXXFLAGS.
$(OBJDIR)cctlib$(OBJ_SUFFIX): cctlib.cpp cctlib.H splay-macros.h
	$(CXX) -Wno-deprecated $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) -DUSE_SHADOW_FOR_DATA_CENTRIC -I$(SPARSEHASH_PATH)/include -I$(BOOST_PATH)/include $(COMP_OBJ)$@ $<

$(OBJDIR)libcctlib$(LIB_SUFFIX): $(OBJDIR)cctlib$(OBJ_SUFFIX)
	$(ARCHIVER)$(OBJDIR)libcctlib$(LIB_SUFFIX) $<

$(OBJDIR)libcctlib_tree_based$(OBJ_SUFFIX): cctlib.cpp cctlib.H splay-macros.h
	$(CXX) -Wno-deprecated   $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) -DUSE_TREE_BASED_FOR_DATA_CENTRIC -I$(SPARSEHASH_PATH)/include -I$(BOOST_PATH)/include $(COMP_OBJ)$@ $<

$(OBJDIR)libcctlib_tree_based$(LIB_SUFFIX): $(OBJDIR)libcctlib_tree_based$(OBJ_SUFFIX)
	$(ARCHIVER)$(OBJDIR)libcctlib_tree_based$(LIB_SUFFIX) $<


include_HEADERS=cctlib.H


include $(TOOLS_ROOT)/Config/makefile.default.rules



clean-local:
	rm -f *.o *.a

