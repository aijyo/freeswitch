include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_auth

if HAVE_KS

mod_LTLIBRARIES = mod_auth.la
mod_auth_la_SOURCES  = mod_auth.c auth_https.c
mod_auth_la_CFLAGS   = $(CURL_CFLAGS) $(KS_CFLAGS) $(AM_CFLAGS)
mod_auth_la_LIBADD   = $(switch_builddir)/libfreeswitch.la 
mod_auth_la_LDFLAGS  = $(CURL_LIBS) -avoid-version -module -no-undefined -shared $(KS_LIBS)

else
install: error
all: error
error:
	$(error You must install libks to build mod_auth)
endif