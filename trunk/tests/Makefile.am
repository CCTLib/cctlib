#include ../Makefile.inc
all:  cct_client.so  deadspy_client.so cct_data_centric_client.so cct_client_mem_only.so cct_data_centric_client_tree_based.so deadWrites.o threaded.o cctlib_reader.so footprint_client.so
#all:  cct_client.so  deadspy_client.so cct_data_centric_client.so cct_client_mem_only.so cct_data_centric_client_tree_based.so deadWrites 

CCTLIB_TEST_CPPFLAGS = $(CPPFLAGS) -I../src/
CCTLIB_SHADOW_BASED_LIBRARY=../src/libcctlib.a
CCTLIB_TREE_BASED_LIBRARY=../src/libcctlib_tree_based.a

cct_client.so: cct_client.cpp $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   cct_client.cpp 
	$(CXX)   -o cct_client.so cct_client.o -L../src/ -lcctlib  $(LDFLAGS) 


cctlib_reader.so: cctlib_reader.cpp $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   cctlib_reader.cpp 
	$(CXX)   -o cctlib_reader.so cctlib_reader.o -L../src/ -lcctlib  $(LDFLAGS) 

deadspy_client.so: deadspy_client.cpp $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   deadspy_client.cpp 
	$(CXX)   -o deadspy_client.so deadspy_client.o -L../src/ -lcctlib $(LDFLAGS)  


cct_client_mem_only.so: cct_client_mem_only.cpp $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   cct_client_mem_only.cpp
	$(CXX)   -o cct_client_mem_only.so cct_client_mem_only.o -L../src/ -lcctlib $(LDFLAGS) 

cct_data_centric_client.so: cct_data_centric_client.cpp $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   cct_data_centric_client.cpp
	$(CXX)   -o cct_data_centric_client.so cct_data_centric_client.o -L../src/ -lcctlib $(LDFLAGS) 


cct_data_centric_client_tree_based.so: cct_data_centric_client_tree_based.cpp $(CCTLIB_TREE_BASED_LIBRARY) 
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   cct_data_centric_client_tree_based.cpp
	$(CXX)   -o cct_data_centric_client_tree_based.so cct_data_centric_client_tree_based.o -L../src/ -lcctlib_tree_based $(LDFLAGS)  

deadWrites.o: deadWrites.cpp
	 $(CXX) -g -o deadWrites.o deadWrites.cpp

footprint_client.so: footprint_client.cpp $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   footprint_client.cpp
	$(CXX)   -o footprint_client.so footprint_client.o -L../src/ -lcctlib $(LDFLAGS) 

valueNum.so: valueNum.cpp $(CCTLIB_SHADOW_BASED_LIBRARY)
	$(CXX)  $(CXXFLAGS) $(CCTLIB_TEST_CPPFLAGS)   valueNum.cpp
	$(CXX)   -o valueNum.so valueNum.o -L../src/ -lcctlib $(LDFLAGS) 

threaded.o: threaded.c
	 $(CC) -g -fopenmp -o threaded.o threaded.c
clean-local:
	rm -f *.o *.so

