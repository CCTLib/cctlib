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
    $(OBJDIR)/cctlib_integration_test

.PHONY: all test clean
all: $(TESTS)

$(OBJDIR)/%: %.cpp | $(OBJDIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

# Run each test binary. GoogleTest exits non-zero on failure, propagating
# through the `for` loop's `|| exit $$?`. Integration tests need PIN_ROOT
# and CCTLIB_ROOT; forward them explicitly (CCTLIB_ROOT defaults to two
# levels up from this Makefile).
CCTLIB_ROOT ?= $(abspath $(CURDIR)/../..)

test: $(TESTS)
	@for t in $(TESTS); do \
	    echo "== $$t =="; \
	    PIN_ROOT="$(PIN_ROOT)" CCTLIB_ROOT="$(CCTLIB_ROOT)" \
	        $$t --gtest_color=no || exit $$?; \
	done

clean:
	rm -rf obj obj-cov
