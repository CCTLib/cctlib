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
    $(OBJDIR)/omp_race_integration_test \
    $(OBJDIR)/footprint_integration_test \
    $(OBJDIR)/ins_reuse_integration_test \
    $(OBJDIR)/rvn_integration_test \
    $(OBJDIR)/exception_integration_test \
    $(OBJDIR)/exception_shape_test \
    $(OBJDIR)/recursion_integration_test

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
    $(OBJDIR)/apps/footprint_small \
    $(OBJDIR)/apps/footprint_large \
    $(OBJDIR)/apps/ins_reuse_tight_loop \
    $(OBJDIR)/apps/rvn_tp_repeated \
    $(OBJDIR)/apps/rvn_tn_different \
    $(OBJDIR)/apps/isa/deadspy_sse16_tp \
    $(OBJDIR)/apps/isa/deadspy_avx32_tp \
    $(OBJDIR)/apps/isa/deadspy_partial_qword_then_byte_tp \
    $(OBJDIR)/apps/isa/deadspy_partial_qword_then_byte_high_tp \
    $(OBJDIR)/apps/isa/deadspy_repstos_tp \
    $(OBJDIR)/apps/isa/deadspy_xchg_tn \
    $(OBJDIR)/apps/isa/deadspy_addressing_tp \
    $(OBJDIR)/apps/isa/deadspy_cross_page_qword_tp \
    $(OBJDIR)/apps/isa/deadspy_pushpop_dead_tp \
    $(OBJDIR)/apps/isa/deadspy_cmpxchg_tn \
    $(OBJDIR)/apps/isa/deadspy_movnti_tp \
    $(OBJDIR)/apps/isa/deadspy_prefetch_tp \
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
    $(OBJDIR)/apps/isa/loadspy_mixed_widths_tp \
    $(OBJDIR)/apps/isa/footprint_avx32_sweep \
    $(OBJDIR)/apps/isa/ins_reuse_simd_loop \
    $(OBJDIR)/apps/isa/rvn_repeated_add \
    $(OBJDIR)/apps/exceptions/exc_simple_throw \
    $(OBJDIR)/apps/exceptions/exc_deep_unwind \
    $(OBJDIR)/apps/exceptions/exc_rethrow \
    $(OBJDIR)/apps/exceptions/exc_catchall \
    $(OBJDIR)/apps/exceptions/exc_dtor_cleanup \
    $(OBJDIR)/apps/exceptions/exc_stress_loop \
    $(OBJDIR)/apps/exceptions/exc_polymorphic \
    $(OBJDIR)/apps/exceptions/exc_recurse_trycatch \
    $(OBJDIR)/apps/exceptions/exc_none_tn \
    $(OBJDIR)/apps/exceptions/exc_uncaught_tn \
    $(OBJDIR)/apps/exceptions/exc_ctor_throw \
    $(OBJDIR)/apps/exceptions/exc_catch_and_resume \
    $(OBJDIR)/apps/exceptions/sig_longjmp \
    $(OBJDIR)/apps/exceptions/sig_sigsegv_recover \
    $(OBJDIR)/apps/recursion/rec_fib_deep \
    $(OBJDIR)/apps/recursion/rec_ackermann \
    $(OBJDIR)/apps/recursion/rec_multi_direct \
    $(OBJDIR)/apps/recursion/rec_indirect_only \
    $(OBJDIR)/apps/recursion/rec_mixed_direct_indirect \
    $(OBJDIR)/apps/recursion/rec_stripped \
    $(OBJDIR)/apps/recursion/rec_exception \
    $(OBJDIR)/apps/recursion/rec_baseline_nonrec

# OpenMP victims need -fopenmp on both compile and link.
$(OBJDIR)/apps/omp_race_%: apps/omp_race_%.c | $(OBJDIR)/apps
	$(CC) $(VICTIM_CFLAGS) -fopenmp $< -fopenmp -o $@

# ISA victims that use SSE / AVX need the corresponding CPU feature enabled
# at compile time. -O0 preserves inline asm exactly.
ISA_CFLAGS := -O0 -g -Wall -mavx -mavx2 -msse4.2

# C++ exception/signal victims. Built with the host g++, -fexceptions +
# -frtti + -O0, and -fnon-call-exceptions so signal-triggered faults
# also participate in unwinding tests. -Wno-infinite-recursion silences
# GCC's false positive on recursion that terminates via longjmp.
EXC_CXXFLAGS := -O0 -g -Wall -std=c++17 -fexceptions -frtti -fnon-call-exceptions -Wno-infinite-recursion

# Recursion victims. -O0 keeps recursive calls from being inlined /
# tail-call-optimized away (both would defeat the direct-self-call
# classifier the test suite is exercising). -fno-optimize-sibling-calls
# provides belt-and-braces protection against tail-call rewrites on
# compilers that ignore -O0's guarantee. -Wno-infinite-recursion
# silences a static-analyzer warning on rec_exception whose base case
# is a throw rather than a plain return. rec_stripped picks up an
# additional -s at link time via its own pattern rule below.
REC_CXXFLAGS := -O0 -g -Wall -std=c++17 -fno-optimize-sibling-calls -Wno-infinite-recursion

.PHONY: all test clean
all: $(TESTS) $(VICTIMS)

$(OBJDIR)/%: %.cpp | $(OBJDIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OBJDIR)/apps/%: apps/%.c | $(OBJDIR)/apps
	$(CC) $(VICTIM_CFLAGS) $< -o $@

$(OBJDIR)/apps/isa/%: apps/isa/%.c | $(OBJDIR)/apps/isa
	$(CC) $(ISA_CFLAGS) $< -o $@

$(OBJDIR)/apps/exceptions/%: apps/exceptions/%.cpp | $(OBJDIR)/apps/exceptions
	$(CXX) $(EXC_CXXFLAGS) $< -o $@

# rec_stripped: same recipe as other recursion victims but stripped at
# link time so the classifier only has the CALL immediates to work
# from -- no RTN_Name / no debug info / RTN_Size may be 0.
$(OBJDIR)/apps/recursion/rec_stripped: apps/recursion/rec_stripped.cpp | $(OBJDIR)/apps/recursion
	$(CXX) $(REC_CXXFLAGS) $< -o $@
	strip -s $@

$(OBJDIR)/apps/recursion/rec_exception: apps/recursion/rec_exception.cpp | $(OBJDIR)/apps/recursion
	$(CXX) $(REC_CXXFLAGS) -fexceptions -frtti $< -o $@

$(OBJDIR)/apps/recursion/%: apps/recursion/%.cpp | $(OBJDIR)/apps/recursion
	$(CXX) $(REC_CXXFLAGS) $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/apps:
	mkdir -p $(OBJDIR)/apps

$(OBJDIR)/apps/isa:
	mkdir -p $(OBJDIR)/apps/isa

$(OBJDIR)/apps/exceptions:
	mkdir -p $(OBJDIR)/apps/exceptions

$(OBJDIR)/apps/recursion:
	mkdir -p $(OBJDIR)/apps/recursion

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
