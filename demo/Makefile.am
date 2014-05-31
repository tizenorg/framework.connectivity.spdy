
noinst_PROGRAMS = server client req_rsp req_rsp_http_get req_rsp_http_post req_rsp_http_put req_rsp_http_delete

server_SOURCES = server.c

client_SOURCES = client.c

req_rsp_SOURCES = req_rsp.c

req_rsp_http_get_SOURCES = req_rsp_http_get.c

req_rsp_http_post_SOURCES = req_rsp_http_post.c

req_rsp_http_put_SOURCES = req_rsp_http_put.c

req_rsp_http_delete_SOURCES = req_rsp_http_delete.c

AM_LDFLAGS = `pkg-config --libs check` `pkg-config --libs zlib` `pkg-config --libs openssl`

LDADD = $(top_builddir)/src/libspdy.la

AM_CFLAGS = `pkg-config --cflags check` -I$(top_srcdir)/include

