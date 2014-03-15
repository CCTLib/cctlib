#include ../Makefile.inc
all:  cct_client.so  deadspy_client.so cct_data_centric_client.so cct_client_mem_only.so cct_data_centric_client_tree_based.so deadWrites.o threaded.o cctlib_reader.so 
#all:  cct_client.so  deadspy_client.so cct_data_centric_client.so cct_client_mem_only.so cct_data_centric_client_tree_based.so deadWrites 

CCTLIB_TEST_INCLUDES = $(CCTLIB_INCLUDES) -I../src/
CCTLIB_LIBRARY=../src/libcctlib.a

cct_client.so: cct_client.cpp $(CCTLIB_LIBRARY)
	$(CXX)  $(CFLAGS) $(CCTLIB_TEST_INCLUDES)   cct_client.cpp 
	$(CXX)  $(LINKFLAGS) -o cct_client.so cct_client.o -L../src/ -lcctlib $(CCTLIB_LIBRARIES) 


cctlib_reader.so: cctlib_reader.cpp $(CCTLIB_LIBRARY)
	$(CXX)  $(CFLAGS) $(CCTLIB_TEST_INCLUDES)   cctlib_reader.cpp 
	$(CXX)  $(LINKFLAGS) -o cctlib_reader.so cctlib_reader.o -L../src/ -lcctlib $(CCTLIB_LIBRARIES) 

deadspy_client.so: deadspy_client.cpp $(CCTLIB_LIBRARY)
	$(CXX)  $(CFLAGS) $(CCTLIB_TEST_INCLUDES)   deadspy_client.cpp 
	$(CXX)  $(LINKFLAGS) -o deadspy_client.so deadspy_client.o -L../src/ -lcctlib $(CCTLIB_LIBRARIES)


cct_client_mem_only.so: cct_client_mem_only.cpp $(CCTLIB_LIBRARY)
	$(CXX)  $(CFLAGS) $(CCTLIB_TEST_INCLUDES)   cct_client_mem_only.cpp
	$(CXX)  $(LINKFLAGS) -o cct_client_mem_only.so cct_client_mem_only.o -L../src/ -lcctlib $(CCTLIB_LIBRARIES)

cct_data_centric_client.so: cct_data_centric_client.cpp $(CCTLIB_LIBRARY)
	$(CXX)  $(CFLAGS) $(CCTLIB_TEST_INCLUDES)   cct_data_centric_client.cpp
	$(CXX)  $(LINKFLAGS) -o cct_data_centric_client.so cct_data_centric_client.o -L../src/ -lcctlib $(CCTLIB_LIBRARIES)


cct_data_centric_client_tree_based.so: cct_data_centric_client_tree_based.cpp $(CCTLIB_LIBRARY) 
	$(CXX)  $(CFLAGS) $(CCTLIB_TEST_INCLUDES)   cct_data_centric_client_tree_based.cpp
	$(CXX)  $(LINKFLAGS) -o cct_data_centric_client_tree_based.so cct_data_centric_client_tree_based.o -L../src/ -lcctlib_tree_based $(CCTLIB_LIBRARIES)

deadWrites.o: deadWrites.cpp
	 $(CXX) -g -o deadWrites.o deadWrites.cpp

threaded.o: threaded.c
	 $(CC) -g -fopenmp -o threaded.o threaded.c
clean-local:
	rm -f *.o *.so

