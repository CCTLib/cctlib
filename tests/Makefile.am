#include ../Makefile.inc
#PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

TEST_TOOL_ROOTS =  cct_client cct_data_centric_client cct_client_mem_only cct_data_centric_client_tree_based address_compare
APP_ROOTS = deadWrites threaded

ALLOW_UNUSED_BUT_SET= -Wno-unused-but-set-variable
# -fexceptions/-frtti override Pin's default -fno-* so we can use Google
# sparsehash headers that rely on exceptions and RTTI.
CCTLIB_TEST_FLAGS =  $(CCTLIB_EXTRA_CXXFLAGS)  $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) -fexceptions -frtti -I$(SPARSEHASH_PATH)/include -I../src/ $(ALLOW_UNUSED_BUT_SET)

LIBELF_LD_FLAGS= -L$(LIBELF_PATH)/lib -Wl,-rpath $(LIBELF_PATH)/lib
LIBELF_LIBS = -lelf
CLIENT_LD_FLAGS = $(CCTLIB_EXTRA_LDFLAGS) $(LIBELF_LD_FLAGS)
CLIENT_LIBS = $(LIBELF_LIBS)


CCTLIB_SHADOW_BASED_LIBRARY=../src/$(OBJDIR)libcctlib$(LIB_SUFFIX)
CCTLIB_TREE_BASED_LIBRARY=../src/$(OBJDIR)libcctlib_tree_based$(LIB_SUFFIX)

$(OBJDIR)cct_client$(OBJ_SUFFIX): cct_client.cpp ../src/cctlib.H
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_client$(PINTOOL_SUFFIX): $(OBJDIR)cct_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_data_centric_client$(OBJ_SUFFIX): cct_data_centric_client.cpp ../src/cctlib.H
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_data_centric_client$(PINTOOL_SUFFIX): $(OBJDIR)cct_data_centric_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_client_mem_only$(OBJ_SUFFIX): cct_client_mem_only.cpp ../src/cctlib.H
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_client_mem_only$(PINTOOL_SUFFIX): $(OBJDIR)cct_client_mem_only$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_data_centric_client_tree_based$(OBJ_SUFFIX): cct_data_centric_client_tree_based.cpp ../src/cctlib.H
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_data_centric_client_tree_based$(PINTOOL_SUFFIX): $(OBJDIR)cct_data_centric_client_tree_based$(OBJ_SUFFIX) $(CCTLIB_TREE_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS) -lcctlib_tree_based  $(TOOL_LIBS) $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_metric_client$(OBJ_SUFFIX): cct_metric_client.cpp ../src/cctlib.H
	$(TOOL_CXX)  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_metric_client$(PINTOOL_SUFFIX): $(OBJDIR)cct_metric_client$(OBJ_SUFFIX) $(CCTLIB_TREE_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib_metric  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)address_compare$(OBJ_SUFFIX): address_compare.cpp
	$(TOOL_CXX)  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)address_compare$(PINTOOL_SUFFIX): $(OBJDIR)address_compare$(OBJ_SUFFIX)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)   $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)


# Standalone (non-Pin) unit test for src/shadow_memory.H. Built with the host
# toolchain so it runs directly; no Pin process required. Invoked from the
# top-level `make check` target.
$(OBJDIR)shadow_memory_unittest: shadow_memory_unittest.cpp ../src/shadow_memory.H
	$(CXX) -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter -I../src $< -pthread -o $@

.PHONY: shadow_memory_unittest_run
shadow_memory_unittest_run: $(OBJDIR)shadow_memory_unittest
	./$(OBJDIR)shadow_memory_unittest

# Standalone unit test for the CCT deserialize splay-tree insertion pattern
# (src/cctlib.cpp DeserializeCCTNode). Verifies both the buggy and fixed
# variants and asserts the buggy variant fails as expected.
$(OBJDIR)splay_deserialize_test: splay_deserialize_test.cpp ../src/splay-macros.h
	$(CXX) -O2 -std=c++17 -Wall -Wextra -I../src $< -o $@

.PHONY: splay_deserialize_test_run
splay_deserialize_test_run: $(OBJDIR)splay_deserialize_test
	./$(OBJDIR)splay_deserialize_test


include $(TOOLS_ROOT)/Config/makefile.default.rules

clean-local:
	rm -f $(OBJDIR)/*
