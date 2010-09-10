
PKGCFG_DEPS=librtmp openssl
DEPS=-lev `pkg-config --cflags --libs $(PKGCFG_DEPS)`
OPTS=-g
CC=gcc

default:
	ragel rtmp.rl
	$(CC) $(OPTS) $(DEPS) mediaserver.c librtmp.c rtmp.c
dot:
	ragel -V rtmp.rl > rtmp.dot
	dot rtmp.dot -Tps > rtmp.ps

