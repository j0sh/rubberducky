dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
AC_INIT([rubberducky],
        [m4_esyscmd([./git-version-gen .tarball-version])],
        [])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip foreign subdir-objects])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT("/usr")

AC_PROG_CC_C99

AC_CONFIG_HEADER([config.h])

AX_CHECK_LIBRARY([LIBEV], [ev.h], [ev], [],
   [AC_MSG_ERROR([libev not found, rubberducky requires libev])])

PKG_CHECK_MODULES([RTMP], [librtmp >= v2.3])
CFLAGS="$CFLAGS $RTMP_CFLAGS"
LIBS="$LIBS $RTMP_LIBS"

PKG_CHECK_MODULES([OPENSSL], [openssl])
CFLAGS="$CFLAGS $OPENSSL_CFLAGS"
LIBS="$LIBS $OPENSSL_LIBS"

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
