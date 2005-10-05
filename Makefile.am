lib_LTLIBRARIES=libtpm.la
noinst_PROGRAMS=create_tpm_key

libtpm_la_LIBADD=@OPENSSL_LIB_DIR@/libcrypto.a
libtpm_la_LDFLAGS=-lc
libtpm_la_CFLAGS=-I@OPENSSL_INCLUDE_DIR@
libtpm_la_SOURCES=e_tpm.c e_tpm.h e_tpm_err.c

create_tpm_key_SOURCES=create_tpm_key.c
create_tpm_key_LDFLAGS=-ltspi
