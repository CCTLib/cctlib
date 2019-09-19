#include Makefile.inc
#PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config


SUBDIRS = src tests clients apps
.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

tests: src
clients: src

clean-local:
	rm -f deadspy.out.* client.out.* src/$(OBJDIR)/*  tests/$(OBJDIR)/* clients/$(OBJDIR)/* apps/$(OBJDIR)/*
	rm -rf cctlib-database-* DeadSpy-CCTLib-database

check:
	rm -f deadspy.out.* client.out.* 
	rm -rf cctlib-database-* DeadSpy-CCTLib-database
	@echo "-----Testing Pin---------" && $(PIN_ROOT)/pin.sh -ifeellucky -- echo hi > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST1----------" && $(PIN_ROOT)/pin.sh -ifeellucky -t tests/$(OBJDIR)/cct_client$(PINTOOL_SUFFIX) -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST2----------" && $(PIN_ROOT)/pin.sh -ifeellucky -t tests/$(OBJDIR)/cct_client_mem_only$(PINTOOL_SUFFIX) -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST3----------" && $(PIN_ROOT)/pin.sh -ifeellucky -t tests/$(OBJDIR)/cct_data_centric_client$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST4----------" && $(PIN_ROOT)/pin.sh -ifeellucky -t tests/$(OBJDIR)/cct_data_centric_client_tree_based$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
if OPT_USE_BOOST
	@echo "----------TEST5----------" && $(PIN_ROOT)/pin.sh -ifeellucky -t clients/$(OBJDIR)/deadspy_client$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST6----------" && $(PIN_ROOT)/pin.sh -ifeellucky -t clients/$(OBJDIR)/deadspy_client$(PINTOOL_SUFFIX)  -- apps/$(OBJDIR)/deadWrites > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST7----------" && $(PIN_ROOT)/pin.sh -ifeellucky -t clients/$(OBJDIR)/cctlib_reader$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
endif
#	@echo "---TEST8 (patience)-----" && $(PIN_ROOT)/pin.sh -ifeellucky -t tests/$(OBJDIR)/cct_data_centric_client_tree_based$(PINTOOL_SUFFIX)  -- tests/$(OBJDIR)/threaded > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "---TEST8 (patience)-----" && $(PIN_ROOT)/pin.sh -ifeellucky -t clients/$(OBJDIR)/redspy_client$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "*************************************************"
	@echo "************* ALL TESTS PASSED ******************"
	@echo "*************************************************"

include $(TOOLS_ROOT)/Config/makefile.default.rules
