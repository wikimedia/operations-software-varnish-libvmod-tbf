# This file is part of vmod-tbf -*- autoconf -*-
# Copyright (C) 2013 Sergey Poznyakoff
#
# Vmod-tbf is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Vmod-tbf is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with vmod-tbf.  If not, see <http://www.gnu.org/licenses/>.
AC_PREREQ(2.69)
AC_INIT([vmod-tbf], 1.0, [gray@gnu.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR(src/vmod_tbf.vcc)
AM_CONFIG_HEADER(config.h)

AC_CANONICAL_SYSTEM
AC_LANG(C)

AM_INIT_AUTOMAKE([1.14 gnu tar-ustar])

AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CC_STDC
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([could not find a C99 compatible compiler])
fi
AC_PROG_CPP

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

# Check for pkg-config
PKG_PROG_PKG_CONFIG

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/sysinfo.h)

# Check for functions
AC_CHECK_FUNCS(sysinfo getloadavg)

# Check for python
AC_CHECK_PROGS(PYTHON, [python], [
	AC_MSG_ERROR([python is not found.])])

# Varnish source tree
AC_ARG_VAR([VARNISHSRC], [path to Varnish source tree])
AC_ARG_WITH([varnish-source],
            AC_HELP_STRING([--with-varnish-source=DIR],
	                   [Varnish sources are located in DIR]),
	    [VARNISHSRC=$withval])

if test -z "$VARNISHSRC"; then
	AC_MSG_ERROR([no Varnish source tree specified])
fi
case "$VARNISHSRC" in
/*) ;;
*)  AC_MSG_ERROR([varnish source path must be absolute pathname])
esac

VARNISHSRC=`cd $VARNISHSRC && pwd`
AC_CHECK_FILE([$VARNISHSRC/include/varnishapi.h],
  [],
  [AC_MSG_FAILURE(["$VARNISHSRC" is not a Varnish source directory])])

# Check that varnishtest is built in the varnish source directory
AC_CHECK_FILE([$VARNISHSRC/bin/varnishtest/varnishtest],
  [],
  [AC_MSG_FAILURE([cannot find "$VARNISHSRC/bin/varnishtest/varnishtest". Please build your varnish source directory])]
)

# vmod installation dir
AC_ARG_VAR([VMODDIR],  [vmod installation directory])
AC_ARG_WITH([vmoddir],
  AC_HELP_STRING([--with-vmoddir=DIR],
                 [install modules to DIR]),
  [case "$withval" in
   /*)   VMODDIR=$withval;;
   no)   unset VMODDIR;;
   *)    AC_MSG_ERROR([argument to --with-vmoddir must be absolute pathname])
   esac],[VMODDIR=`pkg-config --variable=vmoddir varnishapi`
   if test -z "$VMODDIR"; then
	AC_MSG_FAILURE([cannot determine vmod installation directory])
   fi])


if test -z "$VMODDIR"; then
       VMODDIR='$(libdir)/varnish/mods'
fi

###########
# Check for db.h and libdb
#
AC_CHECK_HEADER([db.h],,[AC_MSG_ERROR([Required header file db.h not found])])

AC_CHECK_LIB(db, db_create,
  [LIBS="$LIBS -ldb"
   AC_RUN_IFELSE(
     [AC_LANG_PROGRAM([#include "db.h"],
        [int v_major, v_minor, v_patch;
         db_version(&v_major, &v_minor, &v_patch);
         return !(v_major == DB_VERSION_MAJOR
                  && v_minor == DB_VERSION_MINOR
                  && v_patch == DB_VERSION_PATCH);
        ])],
     [],
     [AC_MSG_ERROR([header file db.h is not the same version as libdb])])])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	tests/Makefile
])
AC_OUTPUT

