AC_INIT(cctlib, 0.1, chabbi.milind@gmail.com)
AC_PROG_CXX
AM_INIT_AUTOMAKE

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
AM_CONDITIONAL(OPT_ENABLE_DEVELOP, test "${OPT_ENABLE_DEVELOP}" = "yes")


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



if test "$OPT_ENABLE_DEVELOP" = "yes" ; then
  CFLAGS="-c -g -O0 -Wno-deprecated -Wall -Wno-unknown-pragmas   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX"
  LINKFLAGS="-g -O0 -Wl,--hash-style=sysv -shared -Wl,-Bsymbolic -Wl,--version-script=${PIN_PATH}/source/include/pin/pintool.ver"
else
  CFLAGS="-c -g -O3 -Wno-deprecated -Wall  -Wno-unknown-pragmas  -fomit-frame-pointer -fno-stack-protector -fno-strict-aliasing -DNDEBUG -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX"
  LINKFLAGS="-g -O3 -Wl,--hash-style=sysv -shared -Wl,-Bsymbolic -Wl,--version-script=${PIN_PATH}/source/include/pin/pintool.ver"
fi


CCTLIB_INCLUDES="-I${BOOST_PATH}/include -I${SPARSEHASH_PATH}/src -I${PIN_PATH}/extras/xed2-intel64/include -I${PIN_PATH}/extras/components/include -I${PIN_PATH}/source/include -I${PIN_PATH}/source/include/pin/gen -I${PIN_PATH}/source/include/pin"
CCTLIB_LIBRARIES="-L${BOOST_PATH}/lib -L${PIN_PATH}/extras/xed2-intel64/lib -L${PIN_PATH}/intel64/lib -L${PIN_PATH}/intel64/lib-ext -L${PIN_PATH}/intel64/runtime/cpplibs -lpin -lxed -ldwarf -lelf -ldl -lboost_filesystem"


AC_SUBST([PIN_PATH])
AC_SUBST([SPARSEHASH_PATH])
AC_SUBST([BOOST_PATH])
AC_SUBST([CFLAGS])
AC_SUBST([LINKFLAGS])
AC_SUBST([CCTLIB_INCLUDES])
AC_SUBST([CCTLIB_LIBRARIES])

AC_MSG_NOTICE([  Pin:         ${PIN_PATH}])
AC_MSG_NOTICE([  Google sparse hash:         ${SPARSEHASH_PATH}])
AC_MSG_NOTICE([  Boost:         ${BOOST_PATH}])

AC_OUTPUT(Makefile src/Makefile tests/Makefile)