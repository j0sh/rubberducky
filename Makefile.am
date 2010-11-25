ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = rubberducky

rubberducky_CPPFLAGS = $(AM_CPPFLAGS) $(LIBEV_CPPFLAGS)
rubberducky_LDFLAGS = $(AM_LDFLAGS) $(LIBEV_LDFLAGS)
rubberducky_LDADD = -lev

dist_rubberducky_SOURCES = mediaserver.c \
			   rtmp.c \
		      	   rtmpfuncs.c \
		      	   amf.c \
		      	   radixtree/radix.c

INCLUDES = -I$(srcdir) -I. -I$(srcdir)/radixtree -Iradixtree
