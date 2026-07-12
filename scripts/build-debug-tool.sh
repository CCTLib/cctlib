#!/bin/bash
# Build one cctlib client tool with debug flags (-g -O0 -fno-omit-frame-pointer).
#
# The stock cctlib Makefiles use -O3 -fomit-frame-pointer even under
# DEBUG=1, which makes gdb backtraces useless. This script overrides the
# compile line to produce a properly debuggable build.
#
# Usage: scripts/build-debug-tool.sh <tool-name>
#   Example: scripts/build-debug-tool.sh deadspy_client
#
# Rebuilds libcctlib.a AND the requested tool. Preserves the release
# build under obj-intel64/ by NOT running `make clean` first — you may
# want to run this script, debug, then rebuild the release copy with
# `make -C clients` when done.
set -eu

if [ $# -ne 1 ]; then
    echo "Usage: $0 <tool-name>   (e.g. deadspy_client, redspy_client, loadspy_client)" >&2
    exit 2
fi
TOOL="$1"

CCTLIB=${CCTLIB:-$(cd "$(dirname "$0")/.." && pwd)}
: "${PIN_ROOT:?PIN_ROOT must be set to the Pin install root}"
LIBELF_INC="$CCTLIB/libelf-0.8.9-install/include"
JSON_INC="$CCTLIB/json-v3.7.3-install/include"
SPARSEHASH_INC="$CCTLIB/sparsehash-2.0.3-95e5e93-install/include"
LIBELF_LIB="$CCTLIB/libelf-0.8.9-install/lib"

PINGXX="$PIN_ROOT/intel64/pinrt/bin/pin-g++"
COMMON_FLAGS="-Wno-deprecated -DNDEBUG -g -std=c++17 -Wall \
  -Wno-unknown-pragmas -fno-stack-protector -funwind-tables \
  -fasynchronous-unwind-tables -fPIC -Wno-dangling-pointer -faligned-new \
  -I$PIN_ROOT/source/include/pin -I$PIN_ROOT/source/include/pin/gen \
  -isystem $PIN_ROOT/intel64/pinrt/include/adaptor \
  -I$PIN_ROOT/extras/components/include \
  -I$PIN_ROOT/extras/xed-intel64/include/xed \
  -I$PIN_ROOT/source/tools/Utils \
  -O0 -fno-omit-frame-pointer -fno-strict-aliasing \
  -I$JSON_INC -I$SPARSEHASH_INC \
  -Wno-unused-but-set-variable"

echo "==> Rebuilding libcctlib.a with debug flags"
cd "$CCTLIB/src"
mkdir -p obj-intel64
$PINGXX $COMMON_FLAGS -DUSE_SHADOW_FOR_DATA_CENTRIC -fexceptions -frtti \
    -I"$LIBELF_INC" -c -o obj-intel64/cctlib.o cctlib.cpp
rm -f obj-intel64/libcctlib.a
ar cr obj-intel64/libcctlib.a obj-intel64/cctlib.o

echo "==> Rebuilding $TOOL with debug flags"
cd "$CCTLIB/clients"
mkdir -p obj-intel64
$PINGXX $COMMON_FLAGS -fexceptions -frtti \
    -I../src -c -o "obj-intel64/${TOOL}.o" "${TOOL}.cpp"

echo "==> Linking obj-intel64/${TOOL}.so"
$PINGXX -shared -Wl,-Bsymbolic \
    -Wl,--version-script="$PIN_ROOT/source/include/pin/pintool.ver" \
    -o "obj-intel64/${TOOL}.so" "obj-intel64/${TOOL}.o" \
    -L../src/obj-intel64/ \
    -L"$PIN_ROOT/intel64/lib" \
    -L"$PIN_ROOT/extras/xed-intel64/lib" \
    -lcctlib -lpin -lpinrt-adaptor-static -lxed -lpindwarf -ldwarf \
    -lunwind-dynamic \
    -L"$LIBELF_LIB" -Wl,-rpath "$LIBELF_LIB" -lelf

echo
echo "Done. Debug build at: $CCTLIB/clients/obj-intel64/${TOOL}.so"
file "$CCTLIB/clients/obj-intel64/${TOOL}.so"
