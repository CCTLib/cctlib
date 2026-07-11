# Host-toolchain unit tests using GoogleTest.
#
# These build with the system g++ (NOT pin-g++) and run standalone -- they
# never load Pin. Wired from the top-level Makefile's `check` target via
# `make -C tests/gtest test`.

CXX      ?= g++
CXXFLAGS ?= -O0 -g -std=c++17 -Wall -Wextra -Wno-unused-parameter
CPPFLAGS ?= -I../../src
LDLIBS   ?= -lgtest -lgtest_main -lpthread

# Coverage: when make invokes us with COVERAGE=1, add gcov flags and
# tag the objdir so incremental builds don't collide with the plain
# build.
ifeq ($(COVERAGE),1)
    CXXFLAGS += -fprofile-arcs -ftest-coverage
    LDFLAGS  += -fprofile-arcs -ftest-coverage
    OBJDIR   := obj-cov
else
    OBJDIR   := obj
endif

TESTS := \
    $(OBJDIR)/shadow_memory_test \
    $(OBJDIR)/splay_deserialize_test \
    $(OBJDIR)/rbtree_test \
    $(OBJDIR)/cctlib_integration_test \
    $(OBJDIR)/deadspy_integration_test \
    $(OBJDIR)/redspy_integration_test \
    $(OBJDIR)/loadspy_integration_test \
    $(OBJDIR)/cache_client_integration_test \
    $(OBJDIR)/omp_race_integration_test

# Victim programs used by integration tests. Built with the HOST toolchain
# (not pin-g++); they are the TARGET that Pin instruments, not Pin tools
# themselves. -O0 keeps the compiler from collapsing the write patterns
# each test measures.
VICTIM_CFLAGS := -O0 -g -Wall
VICTIMS := \
    $(OBJDIR)/apps/deadspy_tp_simple \
    $(OBJDIR)/apps/deadspy_tn_simple \
    $(OBJDIR)/apps/deadspy_tp_sizes \
    $(OBJDIR)/apps/deadspy_tp_minimal \
    $(OBJDIR)/apps/redspy_tp_simple \
    $(OBJDIR)/apps/redspy_tn_simple \
    $(OBJDIR)/apps/redspy_tp_sizes \
    $(OBJDIR)/apps/loadspy_tp_simple \
    $(OBJDIR)/apps/loadspy_tn_simple \
    $(OBJDIR)/apps/omp_race_tp_simple \
    $(OBJDIR)/apps/omp_race_tn_critical \
    $(OBJDIR)/apps/isa/deadspy_sse16_tp \
    $(OBJDIR)/apps/isa/deadspy_avx32_tp \
    $(OBJDIR)/apps/isa/deadspy_partial_qword_then_byte_tp \
    $(OBJDIR)/apps/isa/deadspy_partial_qword_then_byte_high_tp \
    $(OBJDIR)/apps/isa/deadspy_repstos_tp \
    $(OBJDIR)/apps/isa/deadspy_xchg_tp \
    $(OBJDIR)/apps/isa/deadspy_addressing_tp \
    $(OBJDIR)/apps/isa/deadspy_cross_page_qword_tp \
    $(OBJDIR)/apps/isa/deadspy_pushpop_dead_tp \
    $(OBJDIR)/apps/isa/deadspy_cmpxchg_tn \
    $(OBJDIR)/apps/isa/deadspy_movnti_tp \
    $(OBJDIR)/apps/isa/redspy_sse16_tp \
    $(OBJDIR)/apps/isa/redspy_avx32_tp \
    $(OBJDIR)/apps/isa/redspy_immediate_tp \
    $(OBJDIR)/apps/isa/redspy_partial_qword_then_byte_tp \
    $(OBJDIR)/apps/isa/redspy_zero_fill_tp \
    $(OBJDIR)/apps/isa/redspy_scalar_sse_tp \
    $(OBJDIR)/apps/isa/redspy_cross_page_tp \
    $(OBJDIR)/apps/isa/loadspy_sse16_tp \
    $(OBJDIR)/apps/isa/loadspy_avx32_tp \
    $(OBJDIR)/apps/isa/loadspy_repmovs_tp \
    $(OBJDIR)/apps/isa/loadspy_cross_page_tp \
    $(OBJDIR)/apps/isa/loadspy_mixed_widths_tp

# OpenMP victims need -fopenmp on both compile and link.
$(OBJDIR)/apps/omp_race_%: apps/omp_race_%.c | $(OBJDIR)/apps
	$(CC) $(VICTIM_CFLAGS) -fopenmp $< -fopenmp -o $@

# ISA victims that use SSE / AVX need the corresponding CPU feature enabled
# at compile time. -O0 preserves inline asm exactly.
ISA_CFLAGS := -O0 -g -Wall -mavx -mavx2 -msse4.2

.PHONY: all test clean
all: $(TESTS) $(VICTIMS)

$(OBJDIR)/%: %.cpp | $(OBJDIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OBJDIR)/apps/%: apps/%.c | $(OBJDIR)/apps
	$(CC) $(VICTIM_CFLAGS) $< -o $@

$(OBJDIR)/apps/isa/%: apps/isa/%.c | $(OBJDIR)/apps/isa
	$(CC) $(ISA_CFLAGS) $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/apps:
	mkdir -p $(OBJDIR)/apps

$(OBJDIR)/apps/isa:
	mkdir -p $(OBJDIR)/apps/isa

# Run each test binary. GoogleTest exits non-zero on failure, propagating
# through the `for` loop's `|| exit $$?`. Integration tests need PIN_ROOT
# and CCTLIB_ROOT; forward them explicitly (CCTLIB_ROOT defaults to two
# levels up from this Makefile).
CCTLIB_ROOT ?= $(abspath $(CURDIR)/../..)

test: $(TESTS) $(VICTIMS)
	@for t in $(TESTS); do \
	    echo "== $$t =="; \
	    PIN_ROOT="$(PIN_ROOT)" CCTLIB_ROOT="$(CCTLIB_ROOT)" \
	        $$t --gtest_color=no || exit $$?; \
	done

clean:
	rm -rf obj obj-cov
