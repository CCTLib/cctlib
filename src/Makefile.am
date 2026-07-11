#include ../Makefile.inc
#all:  libcctlib.a libcctlib_tree_based.a
#PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

LIB_ROOTS=libcctlib libcctlib_tree_based libcctlib_tree_with_addr libcctlib_metric

# Pin 4.x supplies its own toolchain wrapper (pin-g++) that sets up its
# libc++/musl CRT and injects the right include paths. Use TOOL_CXX so
# CCTLib is compiled with the same flags as the Pin tools that link it.
# We override Pin's default -fno-exceptions/-fno-rtti because Google
# sparsehash headers rely on exceptions and RTTI.
CCTLIB_OVERRIDES = -fexceptions -frtti
CCTLIB_INCLUDES  = -I$(LIBELF_PATH)/include -I$(SPARSEHASH_PATH)/include

$(OBJDIR)cctlib$(OBJ_SUFFIX): cctlib.cpp cctlib.H splay-macros.h
	$(TOOL_CXX) -Wno-deprecated $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) $(CCTLIB_OVERRIDES) -DUSE_SHADOW_FOR_DATA_CENTRIC $(CCTLIB_INCLUDES) $(COMP_OBJ)$@ $<

$(OBJDIR)libcctlib$(LIB_SUFFIX): $(OBJDIR)cctlib$(OBJ_SUFFIX)
	$(ARCHIVER)$(OBJDIR)libcctlib$(LIB_SUFFIX) $<

$(OBJDIR)cctlib_metric$(OBJ_SUFFIX): cctlib.cpp cctlib.H splay-macros.h
	$(TOOL_CXX) -Wno-deprecated $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) $(CCTLIB_OVERRIDES) -DUSE_SHADOW_FOR_DATA_CENTRIC -DHAVE_METRIC_PER_IPNODE $(CCTLIB_INCLUDES) $(COMP_OBJ)$@ $<

$(OBJDIR)libcctlib_metric$(LIB_SUFFIX): $(OBJDIR)cctlib_metric$(OBJ_SUFFIX)
	$(ARCHIVER)$(OBJDIR)libcctlib_metric$(LIB_SUFFIX) $<


$(OBJDIR)libcctlib_tree_based$(OBJ_SUFFIX): cctlib.cpp cctlib.H splay-macros.h
	$(TOOL_CXX) -Wno-deprecated   $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) $(CCTLIB_OVERRIDES) -DUSE_TREE_BASED_FOR_DATA_CENTRIC $(CCTLIB_INCLUDES) $(COMP_OBJ)$@ $<

$(OBJDIR)libcctlib_tree_based$(LIB_SUFFIX): $(OBJDIR)libcctlib_tree_based$(OBJ_SUFFIX)
	$(ARCHIVER)$(OBJDIR)libcctlib_tree_based$(LIB_SUFFIX) $<

$(OBJDIR)libcctlib_tree_with_addr$(OBJ_SUFFIX): cctlib.cpp cctlib.H splay-macros.h
	$(TOOL_CXX) -Wno-deprecated   $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) $(CCTLIB_OVERRIDES) -DUSE_TREE_BASED_FOR_DATA_CENTRIC -DUSE_TREE_WITH_ADDR $(CCTLIB_INCLUDES) $(COMP_OBJ)$@ $<

$(OBJDIR)libcctlib_tree_with_addr$(LIB_SUFFIX): $(OBJDIR)libcctlib_tree_with_addr$(OBJ_SUFFIX)
	$(ARCHIVER)$(OBJDIR)libcctlib_tree_with_addr$(LIB_SUFFIX) $<


include_HEADERS=cctlib.H


include $(TOOLS_ROOT)/Config/makefile.default.rules



clean-local:
	rm -f $(OBJDIR)/*
