
PKGCFG_DEPS=librtmp openssl
DEPS=-lev `pkg-config --cflags --libs $(PKGCFG_DEPS)`
OPTS=-g
CC=gcc

default:
	$(CC) $(OPTS) $(DEPS) mediaserver.c process_messages.c rtmp.c rtmpfuncs.c amf.c

