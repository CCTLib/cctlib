AC_PREREQ(2.57)
AC_INIT(cctlib, 0.1, chabbi.milind@gmail.com)
# The argument here is just something that should be in the current directory
# (for sanity checking)
AC_CONFIG_SRCDIR(README)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_HEADERS([src/config.h])
AC_PROG_CXX
AC_PROG_CC

#-------------------------------------------------
# enable-develop
#-------------------------------------------------

AC_MSG_CHECKING([whether DEVELOP mode is enabled])

OPT_ENABLE_DEVELOP=no

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

#-------------------------------------------------
# Look for libelf
#-------------------------------------------------
AC_CHECK_LIB([elf], [elf_version],[echo "OK!"], [echo "Not found!"; exit -1])

AC_CHECK_HEADER(libelf.h, [echo "OK!"], [echo "Not found!"; exit -1])
AC_CHECK_HEADER(gelf.h, [echo "OK!"], [echo "Not found!"; exit -1])


PIN_PATH=
SPARSEHASH_PATH=
BOOST_PATH=
CCTLIB_INCLUDES=
CCTLIB_LINKFLAGS=

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

AC_ARG_WITH([boost],
  AS_HELP_STRING([--with-boost=PATH],
                 [use given boost installation (absolute path) with CCTLib]),
   [if ( echo "${withval}" | grep -v "^/" >/dev/null 2>&1 ); then
       AC_MSG_ERROR([--with-boost requires absolute path as argument; given '${withval}'])
     fi
     BOOST_PATH=${withval}
   ])

if test "$BOOST_PATH" = "" ; then
AC_MSG_ERROR([--with-boost requires absolute path as argument; given '${withval}'])
fi

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

CXXFLAGS+=" -c -g -Wno-deprecated -Wall -Wno-unknown-pragmas -fPIC"
CPPFLAGS+="  -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E "
LDFLAGS+=" -g "

#############################
# Platform specific setup
#############################
AC_CANONICAL_HOST
# Check for which host we are on and setup a few things
# specifically based on the host
case $host_os in
  darwin* )
        # Do something specific for mac
        CXXFLAGS+=" -DTARGET_MAC"
        ;;
  linux*)
        # Do something specific for linux
        CPPFLAGS+=" -DTARGET_LINUX "
        LDFLAGS+=" -Wl,--hash-style=sysv -shared -Wl,-Bsymbolic -Wl,--version-script=${PIN_PATH}/source/include/pin/pintool.ver"
        ;;
    *)
        #Default Case
        AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

if test "$OPT_ENABLE_DEVELOP" = "yes" ; then
  CXXFLAGS+=" -O0"
  LDFLAGS+=" -O0"
else
  CXXFLAGS+=" -O3 -fomit-frame-pointer -fno-stack-protector -fno-strict-aliasing -DNDEBUG"
  CPPFLAGS+=" -DNDEBUG "
  LDFLAGS+=" -O3"
fi


CPPFLAGS+="-I${BOOST_PATH}/include -I${SPARSEHASH_PATH}/include -I${PIN_PATH}/extras/xed2-intel64/include -I${PIN_PATH}/extras/components/include -I${PIN_PATH}/source/include -I${PIN_PATH}/source/include/pin/gen -I${PIN_PATH}/source/include/pin"
LDFLAGS+=" -Wl,-rpath=${BOOST_PATH}/lib -Wl,-rpath=${PIN_PATH}/extras/xed2-intel64/lib -Wl,-rpath=${PIN_PATH}/intel64/lib -Wl,-rpath=${PIN_PATH}/intel64/lib-ext -Wl,-rpath=${PIN_PATH}/intel64/runtime/cpplibs  -L${BOOST_PATH}/lib -L${PIN_PATH}/extras/xed2-intel64/lib -L${PIN_PATH}/intel64/lib -L${PIN_PATH}/intel64/lib-ext -L${PIN_PATH}/intel64/runtime/cpplibs -lpin -lxed -ldwarf -lelf -ldl -lboost_filesystem"


AC_SUBST([PIN_PATH])
AC_SUBST([SPARSEHASH_PATH])
AC_SUBST([BOOST_PATH])
AC_SUBST([CXXFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([LDFLAGS])
#AC_SUBST([CCTLIB_INCLUDES])
#AC_SUBST([CCTLIB_LIBRARIES])

AC_MSG_NOTICE([  Pin:         ${PIN_PATH}])
AC_MSG_NOTICE([  Google sparse hash:         ${SPARSEHASH_PATH}])
AC_MSG_NOTICE([  Boost:         ${BOOST_PATH}])

# Write generated configuration file
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT
