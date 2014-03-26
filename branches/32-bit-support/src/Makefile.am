#include ../Makefile.inc
#all:  libcctlib.a libcctlib_tree_based.a
lib_LIBRARIES=  libcctlib.a libcctlib_tree_based.a
libcctlib_a_SOURCES=cctlib.cpp cctlib.H splay-macros.h
libcctlib_tree_based_a_SOURCES=cctlib.cpp cctlib.H splay-macros.h
include_HEADERS=cctlib.H
libcctlib_CPPFLAGS=-DUSE_SHADOW_FOR_DATA_CENTRIC
libcctlib_tree_based_CPPFLAGS=-DUSE_TREE_BASED_FOR_DATA_CENTRIC

clean-local:
	rm -f *.o *.a

