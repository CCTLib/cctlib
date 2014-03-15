set -e
PATH_TO_GOOGLE_SPARSE_HASH=/projects/hpc/mc29/software/sparsehash-2.0.2-install/
PATH_TO_PIN=/projects/hpc/mc29/software/pin_rev/pin-2.13-62732-gcc.4.4.7-linux/
PATH_TO_BOOST=/projects/pkgs/boost_1_47_0/
#develop is off by default
#./configure --with-Pin=$PATH_TO_PIN --with-boost=$PATH_TO_BOOST --with-sparse-hash=$PATH_TO_GOOGLE_SPARSE_HASH --enable-develop
./configure --with-Pin=$PATH_TO_PIN --with-boost=$PATH_TO_BOOST --with-sparse-hash=$PATH_TO_GOOGLE_SPARSE_HASH CXXFLAGS="-O2"
make
echo "*********YOU SUCCESSFULLY BUILT CCTLib***********"
# uncomment to run sanity tests
#echo "*********YOU SUCCESSFULLY TESTED CCTLib***********"
#make check

