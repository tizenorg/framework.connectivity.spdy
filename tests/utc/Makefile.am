
bin_PROGRAMS = runtests

runtests_SOURCES = spindly_utc.c

runtests_LDFLAGS = `pkg-config --libs check` `pkg-config --libs zlib`

runtests_LDADD = $(top_builddir)/src/libspdy.la
runtests_DEPENDENCIES = $(top_builddir)/src/libspdy.la
runtests_CFLAGS = `pkg-config --cflags check` -I$(top_srcdir)/include

run: $(bin_PROGRAMS)
	./$(bin_PROGRAMS)
