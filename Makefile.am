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
	$(PIN_PATH)/pin -t tests/cct_client.so -- ls	
	$(PIN_PATH)/pin -t tests/cct_client_mem_only.so -- ls	
	$(PIN_PATH)/pin -t tests/cct_data_centric_client.so  -- ls	
	$(PIN_PATH)/pin -t tests/cct_data_centric_client_tree_based.so  -- ls	
	$(PIN_PATH)/pin -t tests/deadspy_client.so  -- ls	
	$(PIN_PATH)/pin -t tests/deadspy_client.so  -- tests/deadWrites.o
	$(PIN_PATH)/pin -t tests/cctlib_reader.so  -- ls
	$(PIN_PATH)/pin -t tests/cct_data_centric_client_tree_based.so  -- tests/threaded.o
