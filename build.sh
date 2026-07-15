# @COPYRIGHT@
# Licensed under MIT license.
# See LICENSE.TXT file in the project root for more information.
# ==============================================================
#
# CCTLib build script for Intel Pin >= 4.0.
#
# Prereqs:
#   - g++ 10+ (Pin 4.x recommends this)
#   - autoconf, automake
#   - $PIN_ROOT set to an existing Pin 4.x install, e.g.
#       export PIN_ROOT=/path/to/pin-external-4.3-99850-gce5652921-gcc-linux
#     Kits can be downloaded from
#       https://software.intel.com/sites/landingpage/pintool/downloads/
#
# Notes vs older CCTLib:
#   * Boost is no longer used. Pin RT does not support Boost (no RTTI in Pin's
#     libcxx) and the tiny Boost usage that existed (lexical_cast / trim) is
#     covered by C++11.
#   * Pin 4.x ships its own libc++/musl CRT and builds tools via pin-g++/
#     pin-gcc wrappers. CCTLib now uses TOOL_CXX/TOOL_LINKER (from Pin's
#     makefile.config) rather than the system g++.
#   * libstdc++-only flags (-fabi-version=2, -D_GLIBCXX_USE_CXX11_ABI=0) no
#     longer apply and are dropped.
#
# ==============================================================
set -ex
CUR_DIR=`pwd`

if [ -z "$PIN_ROOT" ]; then
    echo "PIN_ROOT is not set."
    echo "Please 'export PIN_ROOT=/path/to/pin-external-4.x-...-gcc-linux' and re-run."
    echo "Download Pin from https://software.intel.com/sites/landingpage/pintool/downloads/"
    exit 1
fi
echo "PIN_ROOT is set to '$PIN_ROOT'"

############## libelf #################################
cd $CUR_DIR/externals/
tar zxf libelf-0.8.9.tar.gz
rm -rf $CUR_DIR/libelf-0.8.9-install
cd libelf-0.8.9
./configure --prefix=$CUR_DIR/libelf-0.8.9-install
make
make install

#### Google sparse hash  ################################
## taken from git hash 95e5e93 via command: git archive --prefix=sparsehash-2.0.3-95e5e93/  -o sparsehash-2.0.3-95e5e93.tar.gz  HEAD
cd $CUR_DIR/externals/
tar zxf sparsehash-2.0.3-95e5e93.tar.gz
rm -rf $CUR_DIR/sparsehash-2.0.3-95e5e93-install/
cd sparsehash-2.0.3-95e5e93
./configure --prefix=$CUR_DIR/sparsehash-2.0.3-95e5e93-install/ CXXFLAGS="-std=c++11 -Wno-class-memaccess"
make
make install

#### json (header-only) ################################
cd $CUR_DIR/externals/
rm -rf $CUR_DIR/json-v3.7.3-install/
unzip -q -d $CUR_DIR/json-v3.7.3-install/ json-v3.7.3.zip

#### CCTLib #############################################
cd $CUR_DIR/

./configure --with-Pin=$PIN_ROOT \
            --with-sparse-hash=$CUR_DIR/sparsehash-2.0.3-95e5e93-install/ \
            --with-libelf=$CUR_DIR/libelf-0.8.9-install/ \
            --with-json=$CUR_DIR/json-v3.7.3-install/
make -j
echo "*********YOU SUCCESSFULLY BUILT CCTLib***********"
make check
echo "*********YOU SUCCESSFULLY TESTED CCTLib***********"

# Install git hooks if inside a git checkout
if [ -d "$CUR_DIR/.git" ] || git -C "$CUR_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    make -C "$CUR_DIR" install-hooks 2>/dev/null || true
fi
