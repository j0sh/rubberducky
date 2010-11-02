
PKGCFG_DEPS=librtmp openssl
DEPS=-lev `pkg-config --cflags --libs $(PKGCFG_DEPS)`
OPTS=-g -Wall
CC=gcc

default:
	$(CC) $(OPTS) $(DEPS) mediaserver.c rtmp.c rtmpfuncs.c amf.c radixtree/radix.c

