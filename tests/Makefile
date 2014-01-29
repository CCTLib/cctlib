include ../Makefile.inc
all:  cct_client.so  deadspy_client.so cct_data_centric_client.so cct_client_mem_only.so cct_data_centric_client_tree_based.so deadWrites cctlib_reader.so
#all:  cct_client.so  deadspy_client.so cct_data_centric_client.so cct_client_mem_only.so cct_data_centric_client_tree_based.so deadWrites 

INCLUDES += -I../src/


cct_client.so: cct_client.cpp
	$(CXX)  $(CFLAGS) $(INCLUDES)   cct_client.cpp 
	$(CXX)  $(LINKFLAGS) -o cct_client.so cct_client.o -L../src/ -lcctlib $(LIBRARIES) 


cctlib_reader.so: cctlib_reader.cpp
	$(CXX)  $(CFLAGS) $(INCLUDES)   cctlib_reader.cpp 
	$(CXX)  $(LINKFLAGS) -o cctlib_reader.so cctlib_reader.o -L../src/ -lcctlib $(LIBRARIES) 

deadspy_client.so: deadspy_client.cpp 
	$(CXX)  $(CFLAGS) $(INCLUDES)   deadspy_client.cpp 
	$(CXX)  $(LINKFLAGS) -o deadspy_client.so deadspy_client.o -L../src/ -lcctlib $(LIBRARIES)


cct_client_mem_only.so: cct_client_mem_only.cpp 
	$(CXX)  $(CFLAGS) $(INCLUDES)   cct_client_mem_only.cpp
	$(CXX)  $(LINKFLAGS) -o cct_client_mem_only.so cct_client_mem_only.o -L../src/ -lcctlib $(LIBRARIES)

cct_data_centric_client.so: cct_data_centric_client.cpp 
	$(CXX)  $(CFLAGS) $(INCLUDES)   cct_data_centric_client.cpp
	$(CXX)  $(LINKFLAGS) -o cct_data_centric_client.so cct_data_centric_client.o -L../src/ -lcctlib $(LIBRARIES)


cct_data_centric_client_tree_based.so: cct_data_centric_client_tree_based.cpp 
	$(CXX)  $(CFLAGS) $(INCLUDES)   cct_data_centric_client_tree_based.cpp
	$(CXX)  $(LINKFLAGS) -o cct_data_centric_client_tree_based.so cct_data_centric_client_tree_based.o -L../src/ -lcctlib_tree_based $(LIBRARIES)

deadWrites: deadWrites.cpp
	 $(CXX) -g -o deadWrites deadWrites.cpp

clean:
	rm -f *.o *.so

