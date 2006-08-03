SUBDIRS=. test

EXTRA_DIST = README  openssl.cnf.sample

lib_LTLIBRARIES=libtpm.la
bin_PROGRAMS=create_tpm_key

libtpm_la_LIBADD=-L@OPENSSL_LIB_DIR@ -lcrypto -lc
libtpm_la_CFLAGS=-I@OPENSSL_INCLUDE_DIR@
libtpm_la_SOURCES=e_tpm.c e_tpm.h e_tpm_err.c

create_tpm_key_SOURCES=create_tpm_key.c
create_tpm_key_LDADD=-ltspi
