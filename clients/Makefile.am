#include ../Makefile.inc
#PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

# All CCTLib client tools. Some (redspy*, loadspy, zerospy*, omp_datarace,
# runtime_value_numbering) exercise very deep Pin APIs that were renamed or
# removed between Pin 2.14 and Pin 4.x. All are ported here.
TEST_TOOL_ROOTS = deadspy_client redspy_client loadspy_client \
                  redspy_temporal_client redspy_spatial_userdefine_client \
                  cct_metric_client cctlib_reader \
                  footprint_client footprint_client2 \
                  runtime_value_numbering_client omp_datarace_client \
                  cache_client ins_reuse_client \
                  zerospy_client zerospy_cachepage zerospy_spatial_client
APP_ROOTS = deadWrites threaded

ALLOW_UNUSED_BUT_SET= -Wno-unused-but-set-variable
# -fexceptions/-frtti override Pin's default -fno-* so we can use Google
# sparsehash / nlohmann headers that rely on exceptions and RTTI.
CCTLIB_TEST_FLAGS = $(CCTLIB_EXTRA_CXXFLAGS) $(CCTLIB_EXTRA_CPPFLAGS) $(TOOL_CXXFLAGS) -fexceptions -frtti -I$(JSON_PATH)/include -I$(SPARSEHASH_PATH)/include -I../src/ $(ALLOW_UNUSED_BUT_SET)

LIBELF_LD_FLAGS= -L$(LIBELF_PATH)/lib -Wl,-rpath $(LIBELF_PATH)/lib
LIBELF_LIBS = -lelf
CLIENT_LD_FLAGS = $(CCTLIB_EXTRA_LDFLAGS) $(LIBELF_LD_FLAGS)
CLIENT_LIBS = $(LIBELF_LIBS)


CCTLIB_SHADOW_BASED_LIBRARY=../src/$(OBJDIR)libcctlib$(LIB_SUFFIX)
CCTLIB_TREE_BASED_LIBRARY=../src/$(OBJDIR)libcctlib_tree_based$(LIB_SUFFIX)


$(OBJDIR)deadspy_client$(OBJ_SUFFIX): deadspy_client.cpp ../src/cctlib.H
	$(TOOL_CXX) -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)deadspy_client$(PINTOOL_SUFFIX): $(OBJDIR)deadspy_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)redspy_client$(OBJ_SUFFIX): redspy_client.cpp ../src/cctlib.H
	$(TOOL_CXX) -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)redspy_client$(PINTOOL_SUFFIX): $(OBJDIR)redspy_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)loadspy_client$(OBJ_SUFFIX): loadspy_client.cpp ../src/cctlib.H
	$(TOOL_CXX) -mavx -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)loadspy_client$(PINTOOL_SUFFIX): $(OBJDIR)loadspy_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)zerospy_client$(OBJ_SUFFIX): zerospy_client.cpp ../src/cctlib.H
	$(TOOL_CXX) -mavx -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)zerospy_client$(PINTOOL_SUFFIX): $(OBJDIR)zerospy_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)zerospy_cachepage$(OBJ_SUFFIX): zerospy_cachepage.cpp ../src/cctlib.H
	$(TOOL_CXX) -mavx -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)zerospy_cachepage$(PINTOOL_SUFFIX): $(OBJDIR)zerospy_cachepage$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)zerospy_spatial_client$(OBJ_SUFFIX): zerospy_spatial_client.cpp ../src/cctlib.H
	$(TOOL_CXX) -mavx -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

# TODO(preexisting-bug): zerospy_spatial_client.cpp defines
# USE_TREE_BASED_FOR_DATA_CENTRIC + USE_TREE_WITH_ADDR before including
# cctlib.H, so the ThreadData / DataHandle_t layout it compiles against
# differs from the layout in the plain libcctlib built with
# USE_SHADOW_FOR_DATA_CENTRIC. The tool currently links against libcctlib
# below, which produces a silent ABI mismatch that manifests as a
# PIN_GetThreadData assertion at first GetDataObjectHandle call. Proper
# fix: link -lcctlib_tree_with_addr instead. Not required for `make check`
# (this tool isn't exercised there); left as-is to keep the port strictly
# to porting.
$(OBJDIR)zerospy_spatial_client$(PINTOOL_SUFFIX): $(OBJDIR)zerospy_spatial_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)redspy_temporal_client$(OBJ_SUFFIX): redspy_temporal_client.cpp ../src/cctlib.H ../src/shadow_memory.H
	$(TOOL_CXX) -mavx -DENABLE_SAMPLING -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)redspy_temporal_client$(PINTOOL_SUFFIX): $(OBJDIR)redspy_temporal_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)omp_datarace_client$(OBJ_SUFFIX): omp_datarace_client.cpp ../src/cctlib.H ../src/shadow_memory.H
	$(TOOL_CXX) -Wno-deprecated  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)omp_datarace_client$(PINTOOL_SUFFIX): $(OBJDIR)omp_datarace_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cctlib_reader$(OBJ_SUFFIX): cctlib_reader.cpp ../src/cctlib.H
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cctlib_reader$(PINTOOL_SUFFIX): $(OBJDIR)cctlib_reader$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)redspy_spatial_userdefine_client$(OBJ_SUFFIX): redspy_spatial_userdefine_client.cpp ../src/cctlib.H
	$(TOOL_CXX)  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)redspy_spatial_userdefine_client$(PINTOOL_SUFFIX): $(OBJDIR)redspy_spatial_userdefine_client$(OBJ_SUFFIX) $(CCTLIB_TREE_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib_tree_with_addr  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)cct_metric_client$(OBJ_SUFFIX): cct_metric_client.cpp ../src/cctlib.H
	$(TOOL_CXX)  $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)cct_metric_client$(PINTOOL_SUFFIX): $(OBJDIR)cct_metric_client$(OBJ_SUFFIX) $(CCTLIB_TREE_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib_metric  $(TOOL_LIBS)   $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

#Value numbering
$(OBJDIR)runtime_value_numbering_client$(OBJ_SUFFIX): runtime_value_numbering_client.cpp ../src/cctlib.H
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS)  $(COMP_OBJ)$@ $<

$(OBJDIR)runtime_value_numbering_client$(PINTOOL_SUFFIX): $(OBJDIR)runtime_value_numbering_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)


#Footprint clients
$(OBJDIR)footprint_client$(OBJ_SUFFIX): footprint_client.cpp ../src/cctlib.H ../src/cctlib.cpp
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS) -DHAVE_METRIC_PER_IPNODE $(COMP_OBJ)$@ $<

$(OBJDIR)footprint_client$(PINTOOL_SUFFIX): $(OBJDIR)footprint_client$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_PER_IPNODE_METRIC_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib_metric  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

$(OBJDIR)footprint_client2$(OBJ_SUFFIX): footprint_client2.cpp ../src/cctlib.H ../src/cctlib.cpp
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS) -DHAVE_METRIC_PER_IPNODE $(COMP_OBJ)$@ $<

$(OBJDIR)footprint_client2$(PINTOOL_SUFFIX): $(OBJDIR)footprint_client2$(OBJ_SUFFIX) $(CCTLIB_SHADOW_BASED_PER_IPNODE_METRIC_LIBRARY)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)  -lcctlib_metric  $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

#cache client
$(OBJDIR)cache_client$(OBJ_SUFFIX): cache_client.cpp
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS) $(COMP_OBJ)$@ $<

$(OBJDIR)cache_client$(PINTOOL_SUFFIX): $(OBJDIR)cache_client$(OBJ_SUFFIX)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)   $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)

#instruction reuse client
$(OBJDIR)ins_reuse_client$(OBJ_SUFFIX): ins_reuse_client.cpp
	$(TOOL_CXX) $(CCTLIB_TEST_FLAGS) $(COMP_OBJ)$@ $<

$(OBJDIR)ins_reuse_client$(PINTOOL_SUFFIX): $(OBJDIR)ins_reuse_client$(OBJ_SUFFIX)
	$(TOOL_LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< -L../src/$(OBJDIR) $(TOOL_LPATHS)   $(TOOL_LIBS)  $(CLIENT_LD_FLAGS) $(CLIENT_LIBS)


include $(TOOLS_ROOT)/Config/makefile.default.rules

clean-local:
	rm -f $(OBJDIR)/*
