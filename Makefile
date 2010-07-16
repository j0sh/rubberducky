
PKGCFG_DEPS=librtmp
DEPS=-lev `pkg-config --cflags --libs $(PKGCFG_DEPS)`
OPTS=-g
CC=gcc

default:
	$(CC) $(OPTS) $(DEPS) mediaserver.c librtmp.c

