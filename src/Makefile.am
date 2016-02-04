pammod_PROGRAMS = pam_superuserauth.so
pammoddir=/lib/security

pam_superuserauth_so_SOURCES = pam_superuserauth.c
pam_superuserauth_so_CFLAGS = -fpic $(GLIB_CFLAGS)
pam_superuserauth_so_LDFLAGS = -shared
pam_superuserauth_so_LDADD = $(PAM_LIBS) $(CRYPT_LIBS) $(GLIB_LIBS)
