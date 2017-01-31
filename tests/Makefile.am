#include ../Makefile.inc
#PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

TEST_TOOL_ROOTS =  cct_client cct_data_centric_client cct_client_mem_only cct_data_centric_client_tree_based 
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

$(OBJDIR)cct_client$(OBJ_SUFFIX): cct_client.cpp ../src/cctlib.H
	$(CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_client$(PINTOOL_SUFFIX): $(OBJDIR)cct_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_data_centric_client$(OBJ_SUFFIX): cct_data_centric_client.cpp ../src/cctlib.H
	$(CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_data_centric_client$(PINTOOL_SUFFIX): $(OBJDIR)cct_data_centric_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_client_mem_only$(OBJ_SUFFIX): cct_client_mem_only.cpp ../src/cctlib.H
	$(CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_client_mem_only$(PINTOOL_SUFFIX): $(OBJDIR)cct_client_mem_only$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_data_centric_client_tree_based$(OBJ_SUFFIX): cct_data_centric_client_tree_based.cpp ../src/cctlib.H
	$(CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_data_centric_client_tree_based$(PINTOOL_SUFFIX): $(OBJDIR)cct_data_centric_client_tree_based$(OBJ_SUFFIX) $(CCTLIB_TREE_BASED_LIBRARY)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS) -lcctlib_tree_based  $(TOOL_LIBS) $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_metric_client$(OBJ_SUFFIX): cct_metric_client.cpp ../src/cctlib.H
	$(CXX)  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_metric_client$(PINTOOL_SUFFIX): $(OBJDIR)cct_metric_client$(OBJ_SUFFIX) $(CCTLIB_TREE_BASED_LIBRARY)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib_metric  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

include $(TOOLS_ROOT)/Config/makefile.default.rules

clean-local:
	rm -f $(OBJDIR)/*

