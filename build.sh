# @COPYRIGHT@
# Licensed under MIT license.
# See LICENSE.TXT file in the project root for more information.
# ==============================================================

set -ex
#PATH_TO_PIN=/home/scratch/xl10/support/pin-2.14-71313-gcc.4.4.7-linux
CUR_DIR=`pwd`
PIN_REV=2.14-71313
LinuxSuffix=gcc.4.4.7-linux.tar.gz
MacSuffix=clang.5.1-mac.tar.gz
PIN_WWW_PREFIX=http://software.intel.com/sites/landingpage/pintool/downloads/
WEB_FETCH=wget
WEB_FETCH_OUTPUT_FLAG=" -O"
os_type=`uname`
echo $os_type

case $os_type in
	Linux*) 
		PIN_FILE_NAME=pin-${PIN_REV}-${LinuxSuffix}
		;;
	Darwin*)
		PIN_FILE_NAME=pin-${PIN_REV}-${MacSuffix}
		WEB_FETCH=wget
		WEB_FETCH_OUTPUT_FLAG=" -O"
		;;
	*) ;;
esac


WWW_PIN_LOC=${PIN_WWW_PREFIX}${PIN_FILE_NAME}
echo ${PIN_WWW_PREFIX}${PIN_FILE_NAME}
PIN_FILE_BASE=`basename ${PIN_FILE_NAME} .tar.gz`

#PIN_ROOT="/home/mc29/CCTLIB_ALL/cctlib/pin-2.14-67254-gcc.4.4.7-linux/"
if [ -z "$PIN_ROOT" ]
then
echo "PIN_ROOT is NOT set!"
echo "  (1) Download Pin from the WWW and automatically set PIN_ROOT?
  (2) Enter PIN_ROOT in the commandline?
  (any key) Exit?"
userVal=
read userVal
case $userVal in
        1) echo wget ${WWW_PIN_LOC}
           $WEB_FETCH ${WWW_PIN_LOC} $WEB_FETCH_OUTPUT_FLAG  ${PIN_FILE_NAME}
           tar zxvf ${PIN_FILE_NAME}
           PIN_ROOT=${CUR_DIR}/${PIN_FILE_BASE}
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
rm -rf $CUR_DIR/libelf-0.8.9-install
cd libelf-0.8.9
./configure --prefix=$CUR_DIR/libelf-0.8.9-install
make
make install
#### Google sparse hash  ################################
## taken from git hash 95e5e93 via command: git archive --prefix=sparsehash-2.0.3-95e5e93/  -o sparsehash-2.0.3-95e5e93.tar.gz  HEAD
cd $CUR_DIR/externals/
tar zxvf sparsehash-2.0.3-95e5e93.tar.gz
rm -rf $CUR_DIR/sparsehash-2.0.3-95e5e93-install/ 
cd sparsehash-2.0.3-95e5e93
./configure --prefix=$CUR_DIR/sparsehash-2.0.3-95e5e93-install/ CXXFLAGS="-std=c++11 -Wno-class-memaccess -fabi-version=2 -D_GLIBCXX_USE_CXX11_ABI=0 " 
make
make install
#### Boost ##############################################
cd $CUR_DIR/externals/
tar jxvf boost_1_71_0.tar.bz2
rm -rf $CUR_DIR/boost_1_71_0-install/
cd boost_1_71_0
sh ./bootstrap.sh --prefix=$CUR_DIR/boost_1_71_0-install/ --with-libraries="filesystem"  cxxflags="-std=c++11 -fabi-version=2 -D_GLIBCXX_USE_CXX11_ABI=0 " 
./b2 -j 4
./b2 filesystem install
#### CCTLib #############################################
cd $CUR_DIR/

PATH_TO_PIN=$PIN_ROOT
PATH_TO_GOOGLE_SPARSE_HASH=$CUR_DIR/sparsehash-2.0.3-95e5e93-install/
PATH_TO_BOOST=$CUR_DIR/boost_1_71_0-install/
PATH_TO_LIBELF=$CUR_DIR/libelf-0.8.9-install/
#develop is off by default
#./configure --with-Pin=$PATH_TO_PIN --with-boost=$PATH_TO_BOOST --with-sparse-hash=$PATH_TO_GOOGLE_SPARSE_HASH --with-libelf=$PATH_TO_LIBELF --enable-develop
./configure --with-Pin=$PATH_TO_PIN --with-boost=$PATH_TO_BOOST --with-sparse-hash=$PATH_TO_GOOGLE_SPARSE_HASH --with-libelf=$PATH_TO_LIBELF
make
echo "*********YOU SUCCESSFULLY BUILT CCTLib***********"
# uncomment to run sanity tests
make check
echo "*********YOU SUCCESSFULLY TESTED CCTLib***********"

