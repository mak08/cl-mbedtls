#
# Makefile for CFFI mbedTLS bindings
#

MKDIR_P = mkdir -p

PREFIX := /usr/local

MBEDTLS_INCLUDES := /usr/local/include/mbedtls
CFLAGS := -I$(MBEDTLS_INCLUDES)

# Building the executable as a prerequisite from the .cl file did not work,
all: ctypes mbed-ctypes.cl mbed_aux.so

mbed-ctypes.cl: ctypes
	./ctypes

%.o: %.c
	gcc -fPIC -g -c $(CFLAGS) -Wall $<

%.so: %.o
	gcc -shared -o lib$(*).so $<

ctypes: ctypes.c
	gcc $(CFLAGS) ctypes.c -o ctypes -lmbedcrypto -lmbedx509 -lmbedtls

install:
	${MKDIR_P} $(PREFIX)/lib
	cp *.so $(PREFIX)/lib