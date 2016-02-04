AC_INIT([libpam-superuserauth], [0.1], [sbalneav@ltsp.org])
AC_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/pam_superuserauth.c])

AC_PREREQ([2.59])
AC_PROG_CC
AM_PROG_CC_C_O

AC_CHECK_HEADER([security/pam_modules.h], ,
                    [AC_MSG_ERROR([PAM headers missing])])
AC_CHECK_LIB(pam, pam_start, [PAM_LIBS="-lpam"],
                AC_MSG_ERROR([PAM library missing]))
AC_SUBST(PAM_LIBS)

AC_CHECK_LIB(crypt, crypt, [CRYPT_LIBS="-lcrypt"],
                AC_MSG_ERROR([crypt library missing]))
AC_SUBST(CRYPT_LIBS)

AC_CONFIG_FILES([Makefile] [src/Makefile] [man/Makefile])
AC_OUTPUT
