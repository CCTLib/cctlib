#include Makefile.inc
SUBDIRS = src tests
.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

tests: src

clean:
	rm -f deadspy.out.* client.out.* src/*.o src/*.a tests/*.o tests/*.so
	rm -rf cctlib-database-* DeadSpy-CCTLib-database

check:
	rm -f deadspy.out.* client.out.* 
	rm -rf cctlib-database-* DeadSpy-CCTLib-database
	@echo "----------TEST1----------" && $(PIN_PATH)/pin -t tests/cct_client.so -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST2----------" && $(PIN_PATH)/pin -t tests/cct_client_mem_only.so -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST3----------" && $(PIN_PATH)/pin -t tests/cct_data_centric_client.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST4----------" && $(PIN_PATH)/pin -t tests/cct_data_centric_client_tree_based.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST5----------" && $(PIN_PATH)/pin -t tests/deadspy_client.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)	
	@echo "----------TEST6----------" && $(PIN_PATH)/pin -t tests/deadspy_client.so  -- tests/deadWrites.o > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST7----------" && $(PIN_PATH)/pin -t tests/cctlib_reader.so  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "---TEST8 (patience)-----" && $(PIN_PATH)/pin -t tests/cct_data_centric_client_tree_based.so  -- tests/threaded.o > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "*************************************************"
	@echo "************* ALL TESTS PASSED ******************"
	@echo "*************************************************"
