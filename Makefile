
PKGCFG_DEPS=libavcodec librtmp
DEPS=-lev `pkg-config --cflags --libs $(PKGCFG_DEPS)`
OPTS=-g

default:
	gcc $(OPTS) $(DEPS) mediaserver.c librtmp.c

