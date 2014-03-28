#include Makefile.inc
PIN_ROOT=$(PIN_PATH)
CONFIG_ROOT=$(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config


SUBDIRS = src tests
.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

tests: src

clean-local:
	rm -f deadspy.out.* client.out.* src/$(OBJDIR)  tests/$(OBJDIR)
	rm -rf cctlib-database-* DeadSpy-CCTLib-database

check:
	rm -f deadspy.out.* client.out.* 
	rm -rf cctlib-database-* DeadSpy-CCTLib-database
	@echo "----------TEST1----------" && $(PIN) -t tests/$(OBJDIR)/cct_client.so -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST2----------" && $(PIN) -t tests/$(OBJDIR)/cct_client_mem_only.so -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST3----------" && $(PIN) -t tests/$(OBJDIR)/cct_data_centric_client.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST4----------" && $(PIN) -t tests/$(OBJDIR)/cct_data_centric_client_tree_based.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST5----------" && $(PIN) -t tests/$(OBJDIR)/deadspy_client.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST6----------" && $(PIN) -t tests/$(OBJDIR)/deadspy_client.so  -- tests/$(OBJDIR)/deadWrites > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST7----------" && $(PIN) -t tests/$(OBJDIR)/cctlib_reader.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "---TEST8 (patience)-----" && $(PIN) -t tests/$(OBJDIR)/cct_data_centric_client_tree_based.so  -- tests/$(OBJDIR)/threaded > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "*************************************************"
	@echo "************* ALL TESTS PASSED ******************"
	@echo "*************************************************"

include $(TOOLS_ROOT)/Config/makefile.default.rules
