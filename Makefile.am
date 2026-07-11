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
	@echo "----UNITTEST: shadow_memory----" && $(MAKE) -C tests shadow_memory_unittest_run > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----UNITTEST: splay_deserialize----" && $(MAKE) -C tests splay_deserialize_test_run > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----UNITTEST: gtest suite----" && $(MAKE) -C tests/gtest test > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "-----Testing Pin---------" && $(PIN_ROOT)/pin -- echo hi > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST1----------" && $(PIN_ROOT)/pin -t tests/$(OBJDIR)/cct_client$(PINTOOL_SUFFIX) -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST2----------" && $(PIN_ROOT)/pin -t tests/$(OBJDIR)/cct_client_mem_only$(PINTOOL_SUFFIX) -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST3----------" && $(PIN_ROOT)/pin -t tests/$(OBJDIR)/cct_data_centric_client$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST4----------" && $(PIN_ROOT)/pin -t tests/$(OBJDIR)/cct_data_centric_client_tree_based$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST5----------" && $(PIN_ROOT)/pin -t clients/$(OBJDIR)/deadspy_client$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST6----------" && $(PIN_ROOT)/pin -t clients/$(OBJDIR)/deadspy_client$(PINTOOL_SUFFIX)  -- apps/$(OBJDIR)/deadWrites$(EXE_SUFFIX) > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "----------TEST7----------" && $(PIN_ROOT)/pin -t clients/$(OBJDIR)/cctlib_reader$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
#	@echo "---TEST8 (patience)-----" && $(PIN_ROOT)/pin -t tests/$(OBJDIR)/cct_data_centric_client_tree_based$(PINTOOL_SUFFIX)  -- tests/$(OBJDIR)/threaded > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "---TEST8 (patience)-----" && $(PIN_ROOT)/pin -t clients/$(OBJDIR)/redspy_client$(PINTOOL_SUFFIX)  -- ls > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "---TEST9 -----" && $(PIN_ROOT)/pin -t clients/$(OBJDIR)/ins_reuse_client$(PINTOOL_SUFFIX)  -- apps/$(OBJDIR)/reuseApp$(EXE_SUFFIX) > /dev/null && echo "----------PASSED---------" || (echo "----------FAILED---------"; exit -1)
	@echo "*************************************************"
	@echo "************* ALL TESTS PASSED ******************"
	@echo "*************************************************"


# Linting: clang-tidy driven by a bear-captured compile_commands.json.
#
# One-time setup on a fresh checkout:
#   sudo apt install clang-tidy bear   # or your distro's equivalent
#   make clean && bear -- make          # produce compile_commands.json
# Then `make lint` (all sources) or `make lint FILES="src/cctlib.cpp"`.
#
# CLANG_TIDY / PIN paths are overridable from the command line.

CLANG_TIDY ?= clang-tidy-15
# cct_data_name and snippet are documentation examples, not part of the build,
# and reference APIs not present in the default configuration. Exclude them
# from the default lint set; caller can add them back via LINT_FILES=... .
LINT_FILES ?= src/cctlib.cpp $(wildcard clients/*.cpp) \
              $(filter-out tests/cct_data_name.cpp tests/snippet.cpp, $(wildcard tests/*.cpp))
LINT_CLANG_RESOURCE_DIR ?= /usr/lib/llvm-15/lib/clang/15.0.6

# Pin runtime extras that pin-g++ adds internally to gcc but which
# bear does not capture (pin-g++ is a wrapper script). clang-tidy needs
# these to parse pin.H, musl libc, libc++. LINT_CLANG_RESOURCE_DIR
# supplies clang's own intrinsic headers (xmmintrin.h, unwind.h, ...)
# that -nostdinc otherwise hides.
LINT_PIN_EXTRA_ARGS = \
  --extra-arg=-Wno-unknown-warning-option \
  --extra-arg=-nostdinc --extra-arg=-nostdinc++ \
  --extra-arg=-isystem --extra-arg=$(PIN_ROOT)/intel64/pinrt/include/c++ \
  --extra-arg=-isystem --extra-arg=$(PIN_ROOT)/intel64/pinrt/include \
  --extra-arg=-isystem --extra-arg=$(PIN_ROOT)/intel64/pinrt/include/pinos \
  --extra-arg=-idirafter --extra-arg=$(LINT_CLANG_RESOURCE_DIR)/include \
  --extra-arg=-DPIN_CRT=1 --extra-arg=-DPIN_RT \
  --extra-arg=-DTARGET_LINUX --extra-arg=-DTARGET_IA32E --extra-arg=-DHOST_IA32E \
  --extra-arg=-D_LIBCPP_HAS_MUSL_LIBC \
  --extra-arg=-D_LIBCPP_DISABLE_AVAILABILITY \
  --extra-arg=-D_arch_long=long

.PHONY: lint
lint: compile_commands.json
	@for f in $(LINT_FILES); do \
	    printf '=== %s ===\n' $$f; \
	    $(CLANG_TIDY) -p . $(LINT_PIN_EXTRA_ARGS) $$f 2>&1 \
	        | grep -E ':[0-9]+:[0-9]+: (warning|error):' || true; \
	done

compile_commands.json:
	@echo "Missing compile_commands.json. Run:" >&2
	@echo "    make clean && bear -- make" >&2
	@exit 1

# Formatting: clang-format driven by .clang-format at the repo root.
# `make format` reformats all C/C++ sources in place.
# `make format-check` fails if any file would change (for CI).
# Override FORMAT_FILES to reformat a subset.

CLANG_FORMAT ?= clang-format-15
FORMAT_FILES ?= $(wildcard src/*.cpp src/*.H src/*.h) \
                $(wildcard clients/*.cpp) \
                $(wildcard tests/*.cpp)

.PHONY: format
format:
	@$(CLANG_FORMAT) -i $(FORMAT_FILES)
	@echo "formatted $(words $(FORMAT_FILES)) files"

.PHONY: format-check
format-check:
	@$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES)

include $(TOOLS_ROOT)/Config/makefile.default.rules
