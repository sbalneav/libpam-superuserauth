AC_INIT([libpam-superuserauth], [0.4], [sbalneav@ltsp.org])
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

AC_ARG_WITH(min-uid,
            AS_HELP_STRING([--with-min-uid=UID],
                           [Minimum userid that we will use superuserauth for.  Defaults to 500]),
            [ MIN_UID="$with_min_uid" ],
            [ MIN_UID=500 ])
AC_DEFINE_UNQUOTED(MIN_UID, [$MIN_UID], [ Minumum UID.])
AC_SUBST(MIN_UID)

AC_CONFIG_FILES([Makefile] [src/Makefile] [man/Makefile])
AC_OUTPUT
