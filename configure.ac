AC_PREREQ(2.57)
AC_INIT(cctlib, 0.1, chabbi.milind@gmail.com)
# The argument here is just something that should be in the current directory
# (for sanity checking)
AC_CONFIG_SRCDIR(README)
AM_INIT_AUTOMAKE([foreign -Werror])
AC_CONFIG_HEADERS([src/config.h])
AC_PROG_CXX
AC_PROG_CC
AC_PROG_RANLIB

#-------------------------------------------------
# enable-develop
#-------------------------------------------------

AC_MSG_CHECKING([whether DEVELOP mode is enabled])

OPT_ENABLE_DEVELOP=no
OPT_USE_BOOST=no

AC_ARG_ENABLE([develop],
  AS_HELP_STRING([--enable-develop],
                 [Build development version (enable debugging)]),
  [case "${enableval}" in
     yes) OPT_ENABLE_DEVELOP="yes" ;;
     no)  OPT_ENABLE_DEVELOP="no" ;;
     *) AC_MSG_ERROR([bad value ${enableval} for --enable-develop]) ;;
   esac],
  [OPT_ENABLE_DEVELOP=no])

AC_MSG_RESULT([${OPT_ENABLE_DEVELOP}])
AM_CONDITIONAL(OPT_ENABLE_DEVELOP, [test "${OPT_ENABLE_DEVELOP}" = "yes"])

DEBUG=0
CCTLIB_EXTRA_CPPFLAGS=
CCTLIB_EXTRA_CXXFLAGS="-Wno-unused-result -Wno-unused-variable -Wno-unused-local-typedefs -Wno-unused-function -std=c++11"

if test "$OPT_ENABLE_DEVELOP" = "yes" ; then
  DEBUG=1
else
  CCTLIB_EXTRA_CPPFLAGS+="-DNDEBUG"
fi

#-------------------------------------------------
# Look for libelf
#-------------------------------------------------
#AC_CHECK_LIB([elf], [elf_version],[echo "OK!"], [echo "Not found!"; exit -1])

#AC_CHECK_HEADER(libelf.h, [echo "OK!"], [echo "Not found!"; exit -1])
#AC_CHECK_HEADER(gelf.h, [echo "OK!"], [echo "Not found!"; exit -1])


PIN_PATH=
PIN_ROOT=
SPARSEHASH_PATH=
BOOST_PATH=
LIBELF_PATH=
CCTLIB_INCLUDES=
CCTLIB_LINKFLAGS=

AC_ARG_WITH([libelf],
  AS_HELP_STRING([--with-libelf=PATH],
                 [use given libelf installation (absolute path) with CCTLib]),
   [if ( echo "${withval}" | grep -v "^/" >/dev/null 2>&1 ); then
       AC_MSG_ERROR([--with-libelf requires absolute path as argument; given '${withval}'])
     fi
     LIBELF_PATH=${withval}
   ])

if test "$LIBELF_PATH" = "" ; then 
AC_MSG_ERROR([--with-libelf requires absolute path as argument; given '${withval}'])
fi


AC_ARG_WITH([Pin],
  AS_HELP_STRING([--with-Pin=PATH],
                 [use given Pin installation (absolute path) with CCTLib]),
   [if ( echo "${withval}" | grep -v "^/" >/dev/null 2>&1 ); then
       AC_MSG_ERROR([--with-Pin requires absolute path as argument; given '${withval}'])
     fi
     PIN_PATH=${withval}
   ])

if test "$PIN_PATH" = "" ; then 
AC_MSG_ERROR([--with-Pin requires absolute path as argument; given '${withval}'])
fi

PIN_ROOT=$PIN_PATH

AC_ARG_WITH([boost],
  AS_HELP_STRING([--with-boost=PATH],
                 [use given boost installation (absolute path) with CCTLib]),
   [if ( echo "${withval}" | grep -v "^/" >/dev/null 2>&1 ); then
       AC_MSG_ERROR([--with-boost requires absolute path as argument; given '${withval}'])
     fi
     BOOST_PATH=${withval}
     CCTLIB_EXTRA_CXXFLAGS+=" -DUSE_BOOST"
     OPT_USE_BOOST="yes"
   ])

AC_MSG_RESULT([${OPT_USE_BOOST}])
AM_CONDITIONAL(OPT_USE_BOOST, [test "${OPT_USE_BOOST}" = "yes"])

AC_ARG_WITH([sparse-hash],
  AS_HELP_STRING([--with-sparse-hash=PATH],
                 [use given google sparse hash installation (absolute path) with CCTLib]),
   [if ( echo "${withval}" | grep -v "^/" >/dev/null 2>&1 ); then
       AC_MSG_ERROR([--with-sparse-hash requires absolute path as argument; given '${withval}'])
     fi
     SPARSEHASH_PATH=${withval}
   ])

if test "$SPARSEHASH_PATH" = "" ; then
AC_MSG_ERROR([--with-sparse-hash requires absolute path as argument; given '${withval}'])
fi


AC_SUBST([PIN_PATH])
AC_SUBST([PIN_ROOT])
AC_SUBST([SPARSEHASH_PATH])
AC_SUBST([BOOST_PATH])
AC_SUBST([LIBELF_PATH])
AC_SUBST([CXXFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([LDFLAGS])
AC_SUBST([DEBUG])
AC_SUBST([CCTLIB_EXTRA_CPPFLAGS])
AC_SUBST([CCTLIB_EXTRA_CXXFLAGS])
#AC_SUBST([CCTLIB_INCLUDES])
#AC_SUBST([CCTLIB_LIBRARIES])

AC_MSG_NOTICE([  Pin:         ${PIN_PATH}])
AC_MSG_NOTICE([  Google sparse hash:         ${SPARSEHASH_PATH}])
AC_MSG_NOTICE([  Boost:         ${BOOST_PATH}])
AC_MSG_NOTICE([  Libelf:         ${LIBELF_PATH}])

# Write generated configuration file
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT
