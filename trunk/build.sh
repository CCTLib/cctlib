set -ex
PATH_TO_GOOGLE_SPARSE_HASH=/projects/hpc/mc29/software/sparsehash-2.0.2
PATH_TO_PIN=/projects/hpc/mc29/software/pin_rev/pin-2.13-62732-gcc.4.4.7-linux/
PATH_TO_BOOST=/projects/pkgs/boost_1_47_0/
#uncomment if you want to clean before building
#make SPARSEHASH_PATH=$PATH_TO_GOOGLE_SPARSE_HASH PIN_PATH=$PATH_TO_PIN BOOST_PATH=$PATH_TO_BOOST clean
make SPARSEHASH_PATH=$PATH_TO_GOOGLE_SPARSE_HASH PIN_PATH=$PATH_TO_PIN BOOST_PATH=$PATH_TO_BOOST
#uncomment if you want to test your build
#make SPARSEHASH_PATH=$PATH_TO_GOOGLE_SPARSE_HASH PIN_PATH=$PATH_TO_PIN BOOST_PATH=$PATH_TO_BOOST check
echo "*********SUCCESS***********"

