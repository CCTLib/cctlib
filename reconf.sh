# @COPYRIGHT@
# Licensed under MIT license.
# See LICENSE.TXT file in the project root for more information.
# ==============================================================

set -ex
autoreconf -ivf
touch configure.ac aclocal.m4 configure Makefile.am Makefile.in src/Makefile.am src/Makefile.in tests/Makefile.am tests/Makefile.in
