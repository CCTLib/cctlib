set -e
#PATH_TO_PIN=/home/mc29/CCTLIB_ALL/pin-2.14-67254-gcc.4.4.7-linux/
CUR_DIR=`pwd`

WWW_PIN_LOC="http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-gcc.4.4.7-linux.tar.gz"

PIN_ROOT="/home/mc29/CCTLIB_ALL/cctlib/pin-2.14-67254-gcc.4.4.7-linux/"
if [ -z "$PIN_ROOT" ]
then
echo "PIN_ROOT is unset"
echo "  (1) Download from the WWW
  (2) Enter in the commandline
  (3) Exit "
userVal=
read userVal
case $userVal in
        1) wget ${WWW_PIN_LOC}
           tar zxvf pin-2.14-67254-gcc.4.4.7-linux.tar.gz
           PIN_ROOT=${CUR_DIR}/pin-2.14-67254-gcc.4.4.7-linux
                ;;
        2) echo "Enter the path to PIN_ROOT" ; read PIN_ROOT
                ;;
        *) exit 1
esac
echo "PIN_ROOT is set to '$PIN_ROOT'"
else
echo "PIN_ROOT is set to '$PIN_ROOT'"
fi

############## libelf #################################
cd $CUR_DIR/externals/
tar zxvf libelf-0.8.9.tar.gz
cd libelf-0.8.9
./configure --prefix=$CUR_DIR/libelf-0.8.9-install
make
make install
#### Google sparse hash  ################################
cd $CUR_DIR/externals/
tar zxvf sparsehash-2.0.2.tar.gz
cd sparsehash-2.0.2
./configure --prefix=$CUR_DIR/sparsehash-2.0.2-install/ CXXFLAGS="-std=c++11"
make
make install
#### Boost ##############################################
cd $CUR_DIR/externals/
tar jxvf boost_1_56_0.tar.bz2
cd boost_1_56_0
sh ./bootstrap.sh --prefix=$CUR_DIR/boost_1_56_0-install/ --with-libraries="filesystem"  cxxflags="-std=c++11"
./b2 -j 4
./b2 install
#### CCTLib #############################################
cd $CUR_DIR/

PATH_TO_PIN=$PIN_ROOT
PATH_TO_GOOGLE_SPARSE_HASH=$CUR_DIR/sparsehash-2.0.2-install/
PATH_TO_BOOST=$CUR_DIR/boost_1_56_0-install/
PATH_TO_LIBELF=$CUR_DIR/libelf-0.8.9-install/
#develop is off by default
#./configure --with-Pin=$PATH_TO_PIN --with-boost=$PATH_TO_BOOST --with-sparse-hash=$PATH_TO_GOOGLE_SPARSE_HASH --with-libelf=$PATH_TO_LIBELF --enable-develop
./configure --with-Pin=$PATH_TO_PIN --with-boost=$PATH_TO_BOOST --with-sparse-hash=$PATH_TO_GOOGLE_SPARSE_HASH --with-libelf=$PATH_TO_LIBELF
make
echo "*********YOU SUCCESSFULLY BUILT CCTLib***********"
# uncomment to run sanity tests
make check
echo "*********YOU SUCCESSFULLY TESTED CCTLib***********"

