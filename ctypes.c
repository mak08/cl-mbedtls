/*
 * Description  Extract info from SSL headers  
 * Author       Michael Kappert 2015
 * Last Modified <michael 2019-12-30 01:59:15>
 */


#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <poll.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "ssl.h"
#include "md.h"
#include "net.h"
#include "certs.h"
#include "ssl_cache.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "pk_internal.h"


int main () {
  FILE *fp;

  fprintf(stdout, "test_srv_crt: %lu\n", strlen(mbedtls_test_srv_crt));

  ////////////////////////////////////////////////////////////////////////////////
  // Create definitions

  fp = fopen("mbed-ctypes.cl", "w");  

  ////////////////////////////////////////////////////////////////////////////////
  // Write header
  fprintf(fp, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
  fprintf(fp, ";;; Generated from ctypes.c, do not edit\n");
  fprintf(fp, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
  fprintf(fp, "\n");
  fprintf(fp, "(in-package mbedtls)\n");
  fprintf(fp, "\n");
  fprintf(fp, "\n");
  
  // Test signedness of char
  //   char is unsigned on ARM and unsigned *char and char* are used interchangeably in the mbedtls source.
  //   Not sure if this matters.
  char c = -1;
  if ( c == -1 ) 
	{
	  fprintf(stdout, "char is signed\n");
	  fprintf(fp, "%s\n", "(warn \"char is signed\")");
	}
  else
	{
	  fprintf(stdout, "char is unsigned\n");
	}

  ////////////////////////////////////////////////////////////////////////////////
  // size_t
  fprintf(fp, "\n");
  if (sizeof(size_t) == sizeof(unsigned int)) 
	{ 
	  fprintf(fp, "(defctype size_t :unsigned-int)\n");
	}
  else if (sizeof(size_t) == sizeof(unsigned long)) 
	{
	  fprintf(fp, "(defctype size_t :unsigned-long)\n");
	}
  else
	{
	  fprintf(fp, "(defctype size_t :|Fixme - could not determine size of size_t|)\n");
	}

  ////////////////////////////////////////////////////////////////////////////////
  // ERRNO
  fprintf(fp, "\n");
  fprintf(fp, "(defconstant EINTR %i)\n", EINTR);  
 
  ////////////////////////////////////////////////////////////////////////////////
  // Posix Compliance
  fprintf(fp, "\n");
  fprintf(fp, "(defconstant _POSIX_C_SOURCE %lu)\n", _POSIX_C_SOURCE);

  ////////////////////////////////////////////////////////////////////////////////
  // Socket info

  fprintf(fp, "\n");
  fprintf(fp, "(defconstant INET_ADDRSTRLEN %i)\n", INET_ADDRSTRLEN);

  fprintf(fp, "\n");
  fprintf(fp, "(defconstant TCP_NODELAY %i)\n", TCP_NODELAY);
  fprintf(fp, "(defconstant IPPROTO_TCP %i)\n", IPPROTO_TCP);
  fprintf(fp, "(defconstant AF_INET %i)\n", AF_INET);


  fprintf(fp, "\n");
  fprintf(fp, "(defconstant POLLIN %i)\n", POLLIN);
  fprintf(fp, "(defconstant POLLOUT %i)\n", POLLOUT);

  fprintf(fp, "\n");
  fprintf(fp, "(defconstant POLLERR %i)\n", POLLERR);
  fprintf(fp, "(defconstant POLLHUP %i)\n", POLLHUP);
  fprintf(fp, "(defconstant POLLNVAL %i)\n", POLLNVAL);

  fprintf(fp, "\n");
  // fprintf(fp, "(defcstruct (pollfd :size %lu))\n", sizeof(struct pollfd));
  fprintf(fp, "(defcstruct pollfd (fd :int) (events :short) (revents :short))\n");

  ////////////////////////////////////////////////////////////////////////////////
  // mbedTLS structure sizes (for memory allocation)
  fprintf(fp, "\n");

  fprintf(fp, "(defcstruct (mbedtls_ssl_context :size %lu))\n", sizeof(mbedtls_ssl_context));
  fprintf(fp, "(defcstruct (mbedtls_ssl_config :size %lu))\n", sizeof(mbedtls_ssl_config));
  fprintf(fp, "(defcstruct (mbedtls_ssl_session :size %lu))\n", sizeof(mbedtls_ssl_session));
  fprintf(fp, "(defcstruct (mbedtls_ssl_cache_context :size %lu))\n", sizeof(mbedtls_ssl_cache_context));

  fprintf(fp, "\n");
  fprintf(fp, "(defcstruct (mbedtls_md_context_t :size %lu))\n", sizeof(mbedtls_md_context_t));
  
  fprintf(fp, "\n");
  // fprintf(fp, "(defcstruct (mbedtls_net_context :size %lu))\n", sizeof(mbedtls_net_context));
  fprintf(fp, "(defcstruct mbedtls_net_context (fd :int))\n");

  fprintf(fp, "\n");
  fprintf(stdout, "Offsetof(mbedtls_x509_crt, next) = %lu\n", offsetof(mbedtls_x509_crt, next));
  size_t offset = offsetof(mbedtls_x509_crt, next);
  fprintf(fp, "(defcstruct (mbedtls_x509_crt :size %lu))\n", sizeof(mbedtls_x509_crt));
  fprintf(fp, "(defcstruct (mbedtls_x509_crt :size %lu)\n\
  (next (:pointer (:struct mbedtls_x509_crt)) :offset %lu))\n", sizeof(mbedtls_x509_crt), offset);
  fprintf(fp, "(defcstruct (mbedtls_x509_crl :size %lu))\n", sizeof(mbedtls_x509_crl));
  fprintf(fp, "(defcstruct (mbedtls_pk_context :size %lu))\n", sizeof(mbedtls_pk_context));
  fprintf(fp, "(defcstruct (mbedtls_pk_info_t :size %lu))\n", sizeof(mbedtls_pk_info_t));
  fprintf(fp, "(defcstruct (mbedtls_pk_type_t :size %lu))\n", sizeof(mbedtls_pk_type_t));

  fprintf(fp, "\n");
  fprintf(fp, "(defcstruct (mbedtls_entropy_context :size %lu))\n", sizeof(mbedtls_entropy_context));

  fprintf(fp, "\n");
  fprintf(fp, "(defcstruct (mbedtls_ctr_drbg_context :size %lu))\n", sizeof(mbedtls_ctr_drbg_context));

  fprintf(fp, "\n");
  fclose(fp);

  return 0;
}
